package tests

import (
	"encoding/base64"
	"errors"
	"fmt"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"git.gammaspectra.live/git/go-away/utils"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func testAction(t *testing.T, pol policy.Policy, expected int, url string) (*http.Response, error) {
	settings := setupDefaultSettings(t)
	var r *http.Response
	err := MakeGoAwayState(pol, settings, func(do func(r *http.Request, errs ...error) (*http.Response, error)) error {
		request, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		request.Header.Set(settings.ClientIpHeader, "127.0.0.1")
		response, err := do(request)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != expected {
			return fmt.Errorf("expected status code %d, got %d", expected, response.StatusCode)
		}
		r = response

		return nil
	})
	return r, err
}

func TestActionPass(t *testing.T) {
	pol, err := policy.NewPolicy(strings.NewReader(
		`
rules:
  - name: test
    conditions: ["true"]
    action: pass
    settings:

`,
	))
	if err != nil {
		t.Fatal(fmt.Errorf("failed to create policy: %w", err))
	}

	_, err = testAction(t, *pol, http.StatusOK, "/test")
	if err != nil {
		t.Fatal(err)
	}
}

func TestActionNone(t *testing.T) {
	pol, err := policy.NewPolicy(strings.NewReader(
		`
rules:
  - name: test
    conditions: ["true"]
    action: none
    settings:

`,
	))
	if err != nil {
		t.Fatal(fmt.Errorf("failed to create policy: %w", err))
	}

	_, err = testAction(t, *pol, http.StatusOK, "/test")
	if err != nil {
		t.Fatal(err)
	}
}

func TestActionDrop(t *testing.T) {
	pol, err := policy.NewPolicy(strings.NewReader(
		`
rules:
  - name: test
    conditions: ["true"]
    action: drop
    settings:

`,
	))
	if err != nil {
		t.Fatal(fmt.Errorf("failed to create policy: %w", err))
	}

	response, err := testAction(t, *pol, http.StatusForbidden, "/test")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 0 {
		t.Fatal(fmt.Errorf("expected empty response, got %s", string(data)))
	}
}

func TestActionDeny(t *testing.T) {
	pol, err := policy.NewPolicy(strings.NewReader(
		`
rules:
  - name: test
    conditions: ["true"]
    action: deny
    settings:

`,
	))
	if err != nil {
		t.Fatal(fmt.Errorf("failed to create policy: %w", err))
	}

	response, err := testAction(t, *pol, http.StatusForbidden, "/test")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal(errors.New("expected non-empty response, got none"))
	}
}

func TestActionBlock(t *testing.T) {
	pol, err := policy.NewPolicy(strings.NewReader(
		`
rules:
  - name: test
    conditions: ["true"]
    action: block
    settings:

`,
	))
	if err != nil {
		t.Fatal(fmt.Errorf("failed to create policy: %w", err))
	}

	response, err := testAction(t, *pol, http.StatusForbidden, "/test")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal(errors.New("expected non-empty response, got none"))
	}
}

func TestActionCode(t *testing.T) {
	pol, err := policy.NewPolicy(strings.NewReader(
		`
rules:
  - name: test
    conditions: ["true"]
    action: code
    settings:
      http-code: 418

`,
	))
	if err != nil {
		t.Fatal(fmt.Errorf("failed to create policy: %w", err))
	}

	_, err = testAction(t, *pol, http.StatusTeapot, "/test")
	if err != nil {
		t.Fatal(err)
	}
}

func TestActionContextResponseHeaders(t *testing.T) {
	pol, err := policy.NewPolicy(strings.NewReader(
		`
rules:
  - name: test
    conditions: ["true"]
    action: context
    settings:
      response-headers:
        X-World-Domination: yes

`,
	))
	if err != nil {
		t.Fatal(fmt.Errorf("failed to create policy: %w", err))
	}

	response, err := testAction(t, *pol, http.StatusOK, "/test")
	if err != nil {
		t.Fatal(err)
	}

	if response.Header.Get("X-World-Domination") != "yes" {
		t.Fatal(fmt.Errorf("expected header set, got %s", response.Header.Get("X-World-Domination")))
	}
}

func TestActionContextSetMetaTags(t *testing.T) {
	pol, err := policy.NewPolicy(strings.NewReader(
		`
rules:
  - name: test-context
    conditions: ["true"]
    action: context
    settings:
      context-set:
        proxy-meta-tags: yes

  - name: test
    conditions: ["true"]
    action: deny

`,
	))
	if err != nil {
		t.Fatal(fmt.Errorf("failed to create policy: %w", err))
	}

	uri, err := url.Parse("/test")
	if err != nil {
		t.Fatal(fmt.Errorf("failed to create policy: %w", err))
	}
	q := uri.Query()
	q.Set("mime-type", "text/html")
	q.Set("content", base64.RawURLEncoding.EncodeToString([]byte(`
<!DOCTYPE html>
<html>
<head>
	<meta name="description" content="test">
</head>
</html>
`)))

	uri.RawQuery = q.Encode()

	response, err := testAction(t, *pol, http.StatusForbidden, uri.String())
	if err != nil {
		t.Fatal(err)
	}

	tags := utils.FetchTagsFromReader(response.Body, "meta")

	if str := func() string {
		for _, t := range tags {
			var is bool
			var val string
			for _, a := range t.Attr {
				if a.Key == "name" && a.Val == "description" {
					is = true
				}
				if a.Key == "content" {
					val = a.Val
				}
			}
			if is {
				return val
			}
		}
		return "NONE"
	}(); str != "test" {
		t.Fatal(fmt.Errorf("expected meta tag with 'test', got %s", str))
	}
}
