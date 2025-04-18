package action

import (
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"github.com/goccy/go-yaml/ast"
	"log/slog"
	"net/http"
)

func init() {
	Register[policy.RuleActionDROP] = func(state challenge.StateInterface, ruleName, ruleHash string, settings ast.Node) (Handler, error) {
		return Drop{}, nil
	}
}

type Drop struct {
}

func (a Drop) Handle(logger *slog.Logger, w http.ResponseWriter, r *http.Request, done func() (backend http.Handler)) (next bool, err error) {
	logger.Info("request dropped")

	if hj, ok := w.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			// drop without sending data
			_ = conn.Close()
			return false, nil
		}
	}

	// fallback

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", "0")
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusForbidden)

	return false, nil
}
