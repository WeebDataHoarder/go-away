package preload_link

import (
	"context"
	"fmt"
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/utils"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"net/http"
	"time"
)

func init() {
	challenge.Runtimes[Key] = FillRegistration
}

const Key = "preload-link"

type Parameters struct {
	Deadline time.Duration `yaml:"preload-early-hint-deadline"`
}

var DefaultParameters = Parameters{
	Deadline: time.Second * 3,
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

	verifier, issuer := challenge.NewKeyVerifier()
	reg.Verify = verifier

	reg.Class = challenge.ClassTransparent

	ob := challenge.NewAwaiter[string]()

	reg.Object = ob

	reg.IssueChallenge = func(w http.ResponseWriter, r *http.Request, key challenge.Key, expiry time.Time) challenge.VerifyResult {
		// this only works on HTTP/2 and HTTP/3

		if r.ProtoMajor < 2 {
			// this can happen if we are an upgraded request from HTTP/1.1 to HTTP/2 in H2C
			if _, ok := w.(http.Pusher); !ok {
				return challenge.VerifyResultSkip
			}
		}

		issuerKey := issuer(key)

		uri, err := challenge.VerifyUrl(r, reg, issuerKey)
		if err != nil {
			return challenge.VerifyResultFail
		}

		// remove redirect args
		values := uri.Query()
		values.Del(challenge.QueryArgRedirect)
		uri.RawQuery = values.Encode()

		// Redirect URI must be absolute to work
		uri.Scheme = utils.GetRequestScheme(r)
		uri.Host = r.Host

		w.Header().Set("Link", fmt.Sprintf("<%s>; rel=\"preload\"; as=\"style\"; fetchpriority=high", uri.String()))
		defer func() {
			// remove old header so it won't show on response!
			w.Header().Del("Link")
		}()
		w.WriteHeader(http.StatusEarlyHints)

		ctx, cancel := context.WithTimeout(r.Context(), params.Deadline)
		defer cancel()
		if result := ob.Await(issuerKey, ctx); result.Ok() {
			// this should serve!
			return challenge.VerifyResultOK
		} else if result == challenge.VerifyResultNone {
			// we hit timeout
			return challenge.VerifyResultFail
		} else {
			return result
		}
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET "+reg.Path+challenge.VerifyChallengeUrlSuffix, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Content-Length", "0")

		data := challenge.RequestDataFromContext(r.Context())
		key := challenge.GetChallengeKeyForRequest(state, reg, data.Expiration(reg.Duration), r)
		issuerKey := issuer(key)

		_, _, token, err := challenge.GetVerifyInformation(r, reg)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
		}

		verifyResult, _ := verifier(key, []byte(token), r)
		if !verifyResult.Ok() {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			w.WriteHeader(http.StatusOK)
		}

		ob.Solve(issuerKey, verifyResult)
		if !verifyResult.Ok() {
			// also give data on other failure when mismatched
			ob.Solve(token, verifyResult)
		}
	})
	reg.Handler = mux

	return nil
}
