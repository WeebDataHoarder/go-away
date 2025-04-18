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
	Register[policy.RuleActionBLOCK] = func(state challenge.StateInterface, ruleName, ruleHash string, settings ast.Node) (Handler, error) {
		return Block{
			Code:     http.StatusForbidden,
			RuleHash: ruleHash,
		}, nil
	}
}

type Block struct {
	Code     int
	RuleHash string
}

func (a Block) Handle(logger *slog.Logger, w http.ResponseWriter, r *http.Request, done func() (backend http.Handler)) (next bool, err error) {
	logger.Info("request blocked")
	data := challenge.RequestDataFromContext(r.Context())

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Connection", "close")
	w.WriteHeader(a.Code)
	_, _ = w.Write([]byte(fmt.Errorf("access blocked: blocked by administrative rule %s/%s", data.Id.String(), a.RuleHash).Error()))

	return false, nil
}
