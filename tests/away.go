package tests

import (
	"git.gammaspectra.live/git/go-away/lib"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"git.gammaspectra.live/git/go-away/lib/settings"
	"net/http"
	"net/http/httptest"
)

var DefaultSettings = policy.StateSettings{
	Cache: nil,
	Backends: map[string]http.Handler{
		"*": MakeTestBackend(),
	},
	MainName:              "go-away/tests",
	MainVersion:           "testing",
	BasePath:              "/.go-away",
	ChallengeResponseCode: http.StatusTeapot,
	ClientIpHeader:        "X-Forwarded-For",
}

func MakeGoAwayState(pol policy.Policy, stateSettings policy.StateSettings, f func(do func(r *http.Request, errs ...error) (*http.Response, error)) error) error {
	state, err := lib.NewState(pol, settings.DefaultSettings, stateSettings)
	if err != nil {
		return err
	}

	return f(func(r *http.Request, errs ...error) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		state.ServeHTTP(recorder, r)
		return recorder.Result(), nil
	})
}
