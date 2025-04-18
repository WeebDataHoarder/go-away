package resource_load

import (
	"fmt"
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"github.com/goccy/go-yaml/ast"
	"html/template"
	"net/http"
	"time"
)

func init() {
	challenge.Runtimes["resource-load"] = FillRegistrationHeader
}

func FillRegistrationHeader(state challenge.StateInterface, reg *challenge.Registration, parameters ast.Node) error {
	reg.Class = challenge.ClassBlocking

	verifier, issuer := challenge.NewKeyVerifier()
	reg.Verify = verifier

	reg.IssueChallenge = func(w http.ResponseWriter, r *http.Request, key challenge.Key, expiry time.Time) challenge.VerifyResult {
		uri, err := challenge.VerifyUrl(r, reg, issuer(key))
		if err != nil {
			return challenge.VerifyResultFail
		}

		// self redirect!
		//TODO: adjust deadline
		w.Header().Set("Refresh", "2; url="+r.URL.String())

		state.ChallengePage(w, r, state.Settings().ChallengeResponseCode, reg, map[string]any{
			"HeaderTags": []template.HTML{
				template.HTML(fmt.Sprintf("<link href=\"%s\" rel=\"stylesheet\" crossorigin=\"use-credentials\">", uri.String())),
			},
		})
		return challenge.VerifyResultNone
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET "+reg.Path+challenge.VerifyChallengeUrlSuffix, challenge.VerifyHandlerFunc(state, reg, nil, func(state challenge.StateInterface, data *challenge.RequestData, w http.ResponseWriter, r *http.Request, verifyResult challenge.VerifyResult, err error, redirect string) {
		//TODO: add other types inside css that need to be loaded!
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Content-Length", "0")
		if !verifyResult.Ok() {
			w.WriteHeader(http.StatusForbidden)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	reg.Handler = mux

	return nil
}
