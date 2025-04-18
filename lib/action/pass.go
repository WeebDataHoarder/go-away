package action

import (
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"github.com/goccy/go-yaml/ast"
	"log/slog"
	"net/http"
)

func init() {
	Register[policy.RuleActionPASS] = func(state challenge.StateInterface, ruleName, ruleHash string, settings ast.Node) (Handler, error) {
		return Pass{}, nil
	}
}

type Pass struct{}

func (a Pass) Handle(logger *slog.Logger, w http.ResponseWriter, r *http.Request, done func() (backend http.Handler)) (next bool, err error) {
	logger.Debug("request passed")
	done().ServeHTTP(w, r)
	return false, nil
}
