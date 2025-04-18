package action

import (
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"github.com/goccy/go-yaml/ast"
	"log/slog"
	"net/http"
)

type Handler interface {
	// Handle An incoming request.
	// If next is true, continue processing
	// If next is false, stop processing. If passing to a backend, done() must be called beforehand to set headers.
	Handle(logger *slog.Logger, w http.ResponseWriter, r *http.Request, done func() (backend http.Handler)) (next bool, err error)
}

type NewFunc func(state challenge.StateInterface, ruleName, ruleHash string, settings ast.Node) (Handler, error)

var Register = make(map[policy.RuleAction]NewFunc)
