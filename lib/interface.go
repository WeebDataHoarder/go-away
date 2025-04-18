package lib

import (
	"bytes"
	"crypto/ed25519"
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"git.gammaspectra.live/git/go-away/utils"
	"github.com/google/cel-go/cel"
	"log/slog"
	"maps"
	"net/http"
	"strings"
)

// Defines challenge.StateInterface

var _ challenge.StateInterface

func (state *State) ProgramEnv() *cel.Env {
	return state.programEnv
}

func (state *State) Client() *http.Client {
	return state.client
}

func (state *State) PrivateKey() ed25519.PrivateKey {
	return state.privateKey
}

func (state *State) PublicKey() ed25519.PublicKey {
	return state.publicKey
}

func (state *State) UrlPath() string {
	return state.urlPath
}

func (state *State) ChallengeFailed(r *http.Request, reg *challenge.Registration, err error, redirect string, logger *slog.Logger) {
	if logger == nil {
		logger = state.Logger(r)
	}
	logger.Warn("challenge failed", "challenge", reg.Name, "err", err, "redirect", redirect)

	//TODO: metrics
}

func (state *State) ChallengePassed(r *http.Request, reg *challenge.Registration, redirect string, logger *slog.Logger) {
	if logger == nil {
		logger = state.Logger(r)
	}
	logger.Warn("challenge passed", "challenge", reg.Name, "redirect", redirect)

	//TODO: metrics
}

func (state *State) ChallengeIssued(r *http.Request, reg *challenge.Registration, redirect string, logger *slog.Logger) {
	if logger == nil {
		logger = state.Logger(r)
	}
	logger.Info("challenge issued", "challenge", reg.Name, "redirect", redirect)

	//TODO: metrics
}

func (state *State) Logger(r *http.Request) *slog.Logger {
	return GetLoggerForRequest(r)
}

func (state *State) ChallengePage(w http.ResponseWriter, r *http.Request, status int, reg *challenge.Registration, params map[string]any) {
	data := challenge.RequestDataFromContext(r.Context())
	input := make(map[string]any)
	input["Id"] = data.Id.String()
	input["Random"] = utils.CacheBust()
	if reg != nil {
		input["Challenge"] = reg.Name
		input["Path"] = state.UrlPath()
	}
	input["Theme"] = state.Settings().ChallengeTemplateTheme

	maps.Copy(input, params)

	if _, ok := input["Title"]; !ok {
		input["Title"] = "Checking you are not a bot"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	buf := bytes.NewBuffer(make([]byte, 0, 8192))

	err := templates["challenge-"+state.Settings().ChallengeTemplate+".gohtml"].Execute(buf, input)
	if err != nil {
		state.ErrorPage(w, r, http.StatusInternalServerError, err, "")
	} else {
		w.WriteHeader(status)
		_, _ = w.Write(buf.Bytes())
	}
}

func (state *State) ErrorPage(w http.ResponseWriter, r *http.Request, status int, err error, redirect string) {
	data := challenge.RequestDataFromContext(r.Context())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	buf := bytes.NewBuffer(make([]byte, 0, 8192))

	err2 := templates["challenge-"+state.Settings().ChallengeTemplate+".gohtml"].Execute(buf, map[string]any{
		"Id":          data.Id.String(),
		"Random":      utils.CacheBust(),
		"Error":       err.Error(),
		"Path":        state.UrlPath(),
		"Theme":       state.Settings().ChallengeTemplateTheme,
		"Title":       "Oh no! " + http.StatusText(status),
		"HideSpinner": true,
		"Challenge":   "",
		"Redirect":    redirect,
	})
	if err2 != nil {
		// nested errors!
		panic(err2)
	} else {
		w.WriteHeader(status)
		_, _ = w.Write(buf.Bytes())
	}
}

func (state *State) GetChallenge(id challenge.Id) (*challenge.Registration, bool) {
	reg, ok := state.challenges.Get(id)
	return reg, ok
}

func (state *State) GetChallenges() challenge.Register {
	return state.challenges
}

func (state *State) GetChallengeByName(name string) (*challenge.Registration, bool) {
	reg, _, ok := state.challenges.GetByName(name)
	return reg, ok
}
func (state *State) Settings() policy.Settings {
	return state.settings
}

func (state *State) GetBackend(host string) http.Handler {
	backend, ok := state.Settings().Backends[host]
	if !ok {
		// do wildcard match
		wildcard := "*." + strings.Join(strings.Split(host, ".")[1:], ".")
		backend, ok = state.Settings().Backends[wildcard]

		if !ok {
			// return fallback
			backend = state.Settings().Backends["*"]
		}
	}
	//TODO: dynamic
	return backend
}
