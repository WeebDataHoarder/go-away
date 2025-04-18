package cookie

import (
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/utils"
	"github.com/goccy/go-yaml/ast"
	"net/http"
	"time"
)

func init() {
	challenge.Runtimes[Key] = FillRegistration
}

const Key = "cookie"

func FillRegistration(state challenge.StateInterface, reg *challenge.Registration, parameters ast.Node) error {
	reg.Class = challenge.ClassBlocking

	reg.IssueChallenge = func(w http.ResponseWriter, r *http.Request, key challenge.Key, expiry time.Time) challenge.VerifyResult {
		token, err := reg.IssueChallengeToken(state.PrivateKey(), key, nil, expiry, true)
		if err != nil {
			return challenge.VerifyResultFail
		}

		utils.SetCookie(utils.CookiePrefix+reg.Name, token, expiry, w, r)

		uri, err := challenge.RedirectUrl(r, reg)
		if err != nil {
			return challenge.VerifyResultFail
		}

		http.Redirect(w, r, uri.String(), http.StatusTemporaryRedirect)
		return challenge.VerifyResultNone
	}

	return nil
}
