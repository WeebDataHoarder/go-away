package action

import (
	"fmt"
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"log/slog"
	"net/http"
	"regexp"
)

func init() {
	Register[policy.RuleActionPROXY] = func(state challenge.StateInterface, ruleName, ruleHash string, settings ast.Node) (Handler, error) {
		params := ProxyDefaultSettings

		if settings != nil {
			ymlData, err := settings.MarshalYAML()
			if err != nil {
				return nil, err
			}
			err = yaml.Unmarshal(ymlData, &params)
			if err != nil {
				return nil, err
			}
		}

		if params.Match != "" {
			expr, err := regexp.Compile(params.Match)
			if err != nil {
				return nil, err
			}

			return Proxy{
				Match:   expr,
				Rewrite: params.Rewrite,
				Backend: params.Backend,
			}, nil
		}

		return Proxy{
			Backend: params.Backend,
		}, nil
	}
}

var ProxyDefaultSettings = ProxySettings{}

type ProxySettings struct {
	Match   string `yaml:"proxy-match"`
	Rewrite string `yaml:"proxy-rewrite"`
	Backend string `yaml:"proxy-backend"`
}

type Proxy struct {
	Match   *regexp.Regexp
	Rewrite string
	Backend string
}

func (a Proxy) Handle(logger *slog.Logger, w http.ResponseWriter, r *http.Request, done func() (backend http.Handler)) (next bool, err error) {
	data := challenge.RequestDataFromContext(r.Context())

	backend := data.State.GetBackend(a.Backend)
	if backend == nil {
		return false, fmt.Errorf("backend for %s not found", a.Backend)
	}

	if a.Match != nil {
		// rewrite query
		r.URL.Path = a.Match.ReplaceAllString(r.URL.Path, a.Rewrite)
	}

	// set headers, ignore reply
	_ = done()
	backend.ServeHTTP(w, r)

	return false, nil
}
