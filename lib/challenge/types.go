package challenge

import (
	"crypto/ed25519"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"github.com/google/cel-go/cel"
	"log/slog"
	"net/http"
)

type Id int64

type Class uint8

const (
	// ClassTransparent Transparent challenges work inline in the execution process.
	// These can pass or continue, so more challenges or requests can ve served afterward.
	ClassTransparent = Class(iota)

	// ClassBlocking Blocking challenges must serve a different response to challenge the requester.
	// These can pass or stop, for example, due to serving a challenge
	ClassBlocking
)

type VerifyState uint8

const (
	VerifyStateNone = VerifyState(iota)
	// VerifyStatePass Challenge was just passed on this request
	VerifyStatePass
	// VerifyStateBrief Challenge token was verified but didn't check the challenge
	VerifyStateBrief
	// VerifyStateFull Challenge token was verified and challenge verification was done
	VerifyStateFull
)

func (r VerifyState) String() string {
	switch r {
	case VerifyStatePass:
		return "PASS"
	case VerifyStateBrief:
		return "BRIEF"
	case VerifyStateFull:
		return "FULL"
	default:
		panic("unsupported")
	}
}

type VerifyResult uint8

const (
	// VerifyResultNone A negative pass result, without a token
	VerifyResultNone = VerifyResult(iota)
	// VerifyResultFail A negative pass result, with an invalid token
	VerifyResultFail
	// VerifyResultSkip Challenge was skipped due to precondition
	VerifyResultSkip
	// VerifyResultNotOK A negative pass result, with a valid token
	VerifyResultNotOK

	// VerifyResultOK A positive pass result, with a valid token
	VerifyResultOK
)

func (r VerifyResult) Ok() bool {
	return r >= VerifyResultOK
}

func (r VerifyResult) String() string {
	switch r {
	case VerifyResultNone:
		return "None"
	case VerifyResultFail:
		return "Fail"
	case VerifyResultSkip:
		return "Skip"
	case VerifyResultNotOK:
		return "NotOK"
	case VerifyResultOK:
		return "OK"
	default:
		panic("unsupported")
	}
}

type StateInterface interface {
	ProgramEnv() *cel.Env

	Client() *http.Client
	PrivateKey() ed25519.PrivateKey
	PublicKey() ed25519.PublicKey

	UrlPath() string

	ChallengeFailed(r *http.Request, reg *Registration, err error, redirect string, logger *slog.Logger)
	ChallengePassed(r *http.Request, reg *Registration, redirect string, logger *slog.Logger)
	ChallengeIssued(r *http.Request, reg *Registration, redirect string, logger *slog.Logger)

	Logger(r *http.Request) *slog.Logger

	ChallengePage(w http.ResponseWriter, r *http.Request, status int, reg *Registration, params map[string]any)
	ErrorPage(w http.ResponseWriter, r *http.Request, status int, err error, redirect string)

	GetChallenge(id Id) (*Registration, bool)
	GetChallengeByName(name string) (*Registration, bool)
	GetChallenges() Register

	Settings() policy.Settings

	GetBackend(host string) http.Handler
}
