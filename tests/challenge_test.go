package tests

import (
	"encoding/hex"
	"fmt"
	challenge2 "git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"golang.org/x/net/html"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func setupDefaultSettings(t *testing.T) policy.StateSettings {
	settings := DefaultSettings
	slog.SetDefault(slog.New(initLogger(t)))

	return settings
}

func TestChallengeCookie(t *testing.T) {
	settings := setupDefaultSettings(t)

	pol, err := policy.NewPolicy(strings.NewReader(
		`
challenges:
  "challenge-cookie":
    runtime: "cookie"

rules:
  - name: catch-all
    conditions: ["true"]
    action: challenge
    settings:
      challenges: ["challenge-cookie"]

`,
	))
	if err != nil {
		t.Fatal(fmt.Errorf("failed to create policy: %w", err))
	}

	var expectedCode = http.StatusTemporaryRedirect

	err = MakeGoAwayState(*pol, settings, func(do func(r *http.Request, errs ...error) (*http.Response, error)) error {
		challenge, err := http.NewRequest(http.MethodGet, "/test", nil)
		challenge.Header.Set(settings.ClientIpHeader, "127.0.0.1")
		challengeResponse, err := do(challenge)
		if err != nil {
			return err
		}
		defer challengeResponse.Body.Close()
		if challengeResponse.StatusCode != expectedCode {
			return fmt.Errorf("expected challenge status code %d, got %d", expectedCode, challengeResponse.StatusCode)
		} else if cookies := challengeResponse.Cookies(); len(cookies) == 0 {
			return fmt.Errorf("expected set cookies to be non-empty, got none")
		} else if challengeResponse.Header.Get("Location") == "" {
			return fmt.Errorf("expected header 'Location' to be non-empty, got none")
		}

		solveLocation := challengeResponse.Header.Get("Location")

		if !strings.HasPrefix(solveLocation, "/test") {
			return fmt.Errorf("expected next location to start with '/test', got %s", solveLocation)
		}

		// test pass
		pass, err := http.NewRequest(http.MethodGet, solveLocation, nil)
		pass.Header.Set(settings.ClientIpHeader, "127.0.0.1")
		if err != nil {
			return err
		}
		for _, c := range challengeResponse.Cookies() {
			pass.AddCookie(c)
		}

		response, err := do(pass)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("expected pass status code %d, got %d", http.StatusOK, response.StatusCode)
		}

		// test failure
		fail, err := http.NewRequest(http.MethodGet, solveLocation, nil)
		fail.Header.Set(settings.ClientIpHeader, "127.0.0.1")
		if err != nil {
			return err
		}

		response, err = do(fail)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			return fmt.Errorf("expected fail status code %d, got %d", http.StatusForbidden, response.StatusCode)
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestChallengeHeaderRefresh(t *testing.T) {
	settings := setupDefaultSettings(t)

	pol, err := policy.NewPolicy(strings.NewReader(
		`
challenges:
  "challenge-header-refresh":
    runtime: "refresh"
    parameters:
      refresh-via: "header"

rules:
  - name: catch-all
    conditions: ["true"]
    action: challenge
    settings:
      challenges: ["challenge-header-refresh"]

`,
	))
	if err != nil {
		t.Fatal(fmt.Errorf("failed to create policy: %w", err))
	}

	var expectedCode = settings.ChallengeResponseCode

	err = MakeGoAwayState(*pol, settings, func(do func(r *http.Request, errs ...error) (*http.Response, error)) error {
		challenge, err := http.NewRequest(http.MethodGet, "/test", nil)
		challenge.Header.Set(settings.ClientIpHeader, "127.0.0.1")
		challengeResponse, err := do(challenge)
		if err != nil {
			return err
		}
		defer challengeResponse.Body.Close()
		if challengeResponse.StatusCode != expectedCode {
			return fmt.Errorf("expected challenge status code %d, got %d", expectedCode, challengeResponse.StatusCode)
		} else if challengeResponse.Header.Get("Refresh") == "" {
			return fmt.Errorf("expected header 'Refresh' to be non-empty, got none")
		}

		solveLocation, err := url.QueryUnescape(strings.Split(challengeResponse.Header.Get("Refresh"), "; url=")[1])
		if err != nil {
			return err
		}

		// test solve
		solve, err := http.NewRequest(http.MethodGet, solveLocation, nil)
		solve.Header.Set(settings.ClientIpHeader, "127.0.0.1")
		if err != nil {
			return err
		}

		response, err := do(solve)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusTemporaryRedirect {
			return fmt.Errorf("expected solve status code %d, got %d", http.StatusTemporaryRedirect, response.StatusCode)
		} else if cookies := response.Cookies(); len(cookies) == 0 {
			return fmt.Errorf("expected set cookies to be non-empty, got none")
		} else if response.Header.Get("Location") == "" {
			return fmt.Errorf("expected header 'Location' to be non-empty, got none")
		} else if !strings.HasPrefix(response.Header.Get("Location"), "/test") {
			return fmt.Errorf("expected next location to start with '/test', got %s", response.Header.Get("Location"))
		}

		// test pass
		pass, err := http.NewRequest(http.MethodGet, response.Header.Get("Location"), nil)
		pass.Header.Set(settings.ClientIpHeader, "127.0.0.1")
		if err != nil {
			return err
		}
		for _, c := range response.Cookies() {
			pass.AddCookie(c)
		}

		response, err = do(pass)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("expected pass status code %d, got %d", http.StatusOK, response.StatusCode)
		}

		// test failure
		uri, err := url.Parse(solveLocation)
		q := uri.Query()
		q.Set(challenge2.QueryArgToken, hex.EncodeToString(make([]byte, challenge2.KeySize)))
		uri.RawQuery = q.Encode()

		fail, err := http.NewRequest(http.MethodGet, uri.String(), nil)
		fail.Header.Set(settings.ClientIpHeader, "127.0.0.1")
		if err != nil {
			return err
		}

		response, err = do(fail)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			return fmt.Errorf("expected fail status code %d, got %d", http.StatusBadRequest, response.StatusCode)
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestChallengeMetaRefresh(t *testing.T) {
	settings := setupDefaultSettings(t)

	pol, err := policy.NewPolicy(strings.NewReader(
		`
challenges:
  "challenge-meta-refresh":
    runtime: "refresh"
    parameters:
      refresh-via: "meta"

rules:
  - name: catch-all
    conditions: ["true"]
    action: challenge
    settings:
      challenges: ["challenge-meta-refresh"]

`,
	))
	if err != nil {
		t.Fatal(fmt.Errorf("failed to create policy: %w", err))
	}

	var expectedCode = settings.ChallengeResponseCode

	err = MakeGoAwayState(*pol, settings, func(do func(r *http.Request, errs ...error) (*http.Response, error)) error {
		challenge, err := http.NewRequest(http.MethodGet, "/test", nil)
		challenge.Header.Set(settings.ClientIpHeader, "127.0.0.1")
		challengeResponse, err := do(challenge)
		if err != nil {
			return err
		}
		defer challengeResponse.Body.Close()
		if challengeResponse.StatusCode != expectedCode {
			return fmt.Errorf("expected challenge status code %d, got %d", expectedCode, challengeResponse.StatusCode)
		} else if challengeResponse.Header.Get("Refresh") != "" {
			return fmt.Errorf("expected header 'Refresh' to be empty, got \"%s\"", challengeResponse.Header.Get("Refresh"))
		}

		node, err := html.ParseWithOptions(challengeResponse.Body, html.ParseOptionEnableScripting(false))
		if err != nil {
			return nil
		}

		var refresh string
		for n := range node.Descendants() {
			if n.Type == html.ElementNode && n.Data == "meta" {
				var is bool
				var val string
				for _, a := range n.Attr {
					if a.Key == "http-equiv" && a.Val == "refresh" {
						is = true
					}
					if a.Key == "content" {
						val = a.Val
					}
				}
				if is {
					refresh = val
					break
				}
			}
		}

		solveLocation, err := url.QueryUnescape(strings.Split(refresh, "; url=")[1])
		if err != nil {
			return err
		}

		// test solve
		solve, err := http.NewRequest(http.MethodGet, solveLocation, nil)
		solve.Header.Set(settings.ClientIpHeader, "127.0.0.1")
		if err != nil {
			return err
		}

		response, err := do(solve)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusTemporaryRedirect {
			return fmt.Errorf("expected solve status code %d, got %d", http.StatusTemporaryRedirect, response.StatusCode)
		} else if cookies := response.Cookies(); len(cookies) == 0 {
			return fmt.Errorf("expected set cookies to be non-empty, got none")
		} else if response.Header.Get("Location") == "" {
			return fmt.Errorf("expected header 'Location' to be non-empty, got none")
		} else if !strings.HasPrefix(response.Header.Get("Location"), "/test") {
			return fmt.Errorf("expected next location to start with '/test', got %s", response.Header.Get("Location"))
		}

		// test pass
		pass, err := http.NewRequest(http.MethodGet, response.Header.Get("Location"), nil)
		pass.Header.Set(settings.ClientIpHeader, "127.0.0.1")
		if err != nil {
			return err
		}
		for _, c := range response.Cookies() {
			pass.AddCookie(c)
		}

		response, err = do(pass)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return fmt.Errorf("expected pass status code %d, got %d", http.StatusOK, response.StatusCode)
		}

		// test failure
		uri, err := url.Parse(solveLocation)
		q := uri.Query()
		q.Set(challenge2.QueryArgToken, hex.EncodeToString(make([]byte, challenge2.KeySize)))
		uri.RawQuery = q.Encode()

		fail, err := http.NewRequest(http.MethodGet, uri.String(), nil)
		fail.Header.Set(settings.ClientIpHeader, "127.0.0.1")
		if err != nil {
			return err
		}

		response, err = do(fail)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusBadRequest {
			return fmt.Errorf("expected fail status code %d, got %d", http.StatusBadRequest, response.StatusCode)
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
