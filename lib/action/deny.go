package action

import (
	"fmt"
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"github.com/goccy/go-yaml/ast"
	"log/slog"
	"net/http"
)

func init() {
	Register[policy.RuleActionDENY] = func(state challenge.StateInterface, ruleName, ruleHash string, settings ast.Node) (Handler, error) {
		return Deny{
			Code:     http.StatusForbidden,
			RuleHash: ruleHash,
		}, nil
	}
}

type Deny struct {
	Code     int
	RuleHash string
}

func (a Deny) Handle(logger *slog.Logger, w http.ResponseWriter, r *http.Request, done func() (backend http.Handler)) (next bool, err error) {
	logger.Info("request denied")
	data := challenge.RequestDataFromContext(r.Context())
	data.State.ErrorPage(w, r, a.Code, fmt.Errorf("access denied: denied by administrative rule %s/%s", data.Id.String(), a.RuleHash), "")
	return false, nil
}
