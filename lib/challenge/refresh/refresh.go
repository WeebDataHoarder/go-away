package refresh

import (
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"net/http"
	"time"
)

func init() {
	challenge.Runtimes["refresh"] = FillRegistration
}

type Parameters struct {
	Mode string `yaml:"refresh-mode"`
}

var DefaultParameters = Parameters{
	Mode: "header",
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

	reg.Class = challenge.ClassBlocking

	verifier, issuer := challenge.NewKeyVerifier()
	reg.Verify = verifier

	reg.IssueChallenge = func(w http.ResponseWriter, r *http.Request, key challenge.Key, expiry time.Time) challenge.VerifyResult {
		uri, err := challenge.VerifyUrl(r, reg, issuer(key))
		if err != nil {
			return challenge.VerifyResultFail
		}

		if params.Mode == "meta" {
			state.ChallengePage(w, r, state.Settings().ChallengeResponseCode, reg, map[string]any{
				"Meta": map[string]string{
					"refresh": "0; url=" + uri.String(),
				},
			})
		} else {
			// self redirect!
			w.Header().Set("Refresh", "0; url="+uri.String())

			state.ChallengePage(w, r, state.Settings().ChallengeResponseCode, reg, nil)
		}
		return challenge.VerifyResultNone
	}

	return nil
}
