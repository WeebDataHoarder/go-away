package http

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/utils"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"io"
	"net/http"
	"slices"
	"time"
)

func init() {
	challenge.Runtimes[Key] = FillRegistration
}

const Key = "http"

type Parameters struct {
	VerifyProbability float64 `yaml:"verify-probability"`

	HttpMethod string `yaml:"http-method"`
	HttpCode   int    `yaml:"http-code"`
	HttpCookie string `yaml:"http-cookie"`
	Url        string `yaml:"http-url"`
}

var DefaultParameters = Parameters{
	VerifyProbability: 0.20,
	HttpMethod:        http.MethodGet,
	HttpCode:          http.StatusOK,
}

func FillRegistration(state challenge.StateInterface, reg *challenge.Registration, parameters ast.Node) error {
	params := DefaultParameters

	if parameters != nil {
		ymlData, err := parameters.MarshalYAML()
		if err != nil {
			return err
		}
		err = yaml.Unmarshal(ymlData, &params)
		if err != nil {
			return err
		}
	}

	if params.Url == "" {
		return errors.New("empty url")
	}

	reg.Class = challenge.ClassTransparent

	bindAuthValue := func(key challenge.Key, r *http.Request) ([]byte, error) {
		var cookieValue string
		if cookie, err := r.Cookie(params.HttpCookie); err != nil || cookie == nil {
			// skip check if we don't have cookie or it's expired
			return nil, http.ErrNoCookie
		} else {
			cookieValue = cookie.Value
		}

		// bind hash of cookie contents
		sum := sha256.New()
		sum.Write([]byte(cookieValue))
		sum.Write([]byte{0})
		sum.Write(key[:])
		return sum.Sum(nil), nil
	}

	if params.VerifyProbability <= 0 {
		//20% default
		params.VerifyProbability = 0.20
	} else if params.VerifyProbability > 1.0 {
		params.VerifyProbability = 1.0
	}
	reg.VerifyProbability = params.VerifyProbability

	if params.HttpCookie != "" {
		// re-verify the cookie value
		// TODO: configure to verify with backend
		reg.Verify = func(key challenge.Key, token []byte, r *http.Request) (challenge.VerifyResult, error) {
			sum, err := bindAuthValue(key, r)
			if err != nil {
				return challenge.VerifyResultFail, err
			}
			if subtle.ConstantTimeCompare(sum, token) == 1 {
				return challenge.VerifyResultOK, nil
			}
			return challenge.VerifyResultFail, errors.New("invalid cookie value")
		}
	}

	reg.IssueChallenge = func(w http.ResponseWriter, r *http.Request, key challenge.Key, expiry time.Time) challenge.VerifyResult {
		var sum []byte
		if params.HttpCookie != "" {
			if c, err := r.Cookie(params.HttpCookie); err != nil || c == nil {
				// skip check if we don't have cookie or it's expired
				return challenge.VerifyResultSkip
			} else {
				sum, err = bindAuthValue(key, r)
				if err != nil {
					return challenge.VerifyResultFail
				}
			}
		}

		request, err := http.NewRequest(params.HttpMethod, params.Url, nil)
		if err != nil {
			return challenge.VerifyResultFail
		}

		var excludeHeaders = []string{"Host", "Content-Length"}
		for k, v := range r.Header {
			if slices.Contains(excludeHeaders, k) {
				// skip these parameters
				continue
			}
			request.Header[k] = v
		}
		// set id
		request.Header.Set("X-Away-Id", challenge.RequestDataFromContext(r.Context()).Id.String())

		// set request info in X headers
		request.Header.Set("X-Away-Host", r.Host)
		request.Header.Set("X-Away-Path", r.URL.Path)
		request.Header.Set("X-Away-Query", r.URL.RawQuery)

		response, err := state.Client().Do(request)
		if err != nil {
			return challenge.VerifyResultFail
		}
		defer response.Body.Close()
		defer io.Copy(io.Discard, response.Body)

		if response.StatusCode != params.HttpCode {
			token, err := reg.IssueChallengeToken(state.PrivateKey(), key, sum, expiry, false)
			if err != nil {
				return challenge.VerifyResultFail
			}
			utils.SetCookie(utils.CookiePrefix+reg.Name, token, expiry, w, r)
			return challenge.VerifyResultNotOK
		} else {
			token, err := reg.IssueChallengeToken(state.PrivateKey(), key, sum, expiry, true)
			if err != nil {
				return challenge.VerifyResultFail
			}
			utils.SetCookie(utils.CookiePrefix+reg.Name, token, expiry, w, r)
			return challenge.VerifyResultOK
		}
	}

	return nil
}
