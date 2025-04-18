package action

import (
	"fmt"
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"log/slog"
	"net/http"
	"strings"
)

func init() {
	i := func(state challenge.StateInterface, ruleName, ruleHash string, settings ast.Node, cont bool) (Handler, error) {
		params := ChallengeDefaultSettings

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

		if params.Code == 0 {
			params.Code = state.Settings().ChallengeResponseCode
		}

		var regs []*challenge.Registration
		for _, regName := range params.Challenges {
			if reg, ok := state.GetChallengeByName(regName); ok {
				regs = append(regs, reg)
			} else {
				return nil, fmt.Errorf("challenge %s not found", regName)
			}
		}

		if len(regs) == 0 {
			return nil, fmt.Errorf("no registered challenges found in rule %s", ruleName)
		}

		passHandler, ok := Register[policy.RuleAction(strings.ToUpper(params.PassAction))]
		if !ok {
			return nil, fmt.Errorf("unknown pass action %s", params.PassAction)
		}

		passActionHandler, err := passHandler(state, ruleName, ruleHash, params.PassSettings)
		if err != nil {
			return nil, err
		}

		failHandler, ok := Register[policy.RuleAction(strings.ToUpper(params.FailAction))]
		if !ok {
			return nil, fmt.Errorf("unknown pass action %s", params.FailAction)
		}

		failActionHandler, err := failHandler(state, ruleName, ruleHash, params.FailSettings)
		if err != nil {
			return nil, err
		}

		return Challenge{
			RuleHash:   ruleHash,
			Code:       params.Code,
			Continue:   cont,
			Challenges: regs,

			PassAction: passActionHandler,
			FailAction: failActionHandler,
		}, nil
	}
	Register[policy.RuleActionCHALLENGE] = func(state challenge.StateInterface, ruleName, ruleHash string, settings ast.Node) (Handler, error) {
		return i(state, ruleName, ruleHash, settings, false)
	}
	Register[policy.RuleActionCHECK] = func(state challenge.StateInterface, ruleName, ruleHash string, settings ast.Node) (Handler, error) {
		return i(state, ruleName, ruleHash, settings, true)
	}
}

var ChallengeDefaultSettings = ChallengeSettings{
	PassAction: string(policy.RuleActionPASS),
	FailAction: string(policy.RuleActionDENY),
}

type ChallengeSettings struct {
	Code       int      `yaml:"http-code"`
	Challenges []string `yaml:"challenges"`

	PassAction   string   `yaml:"pass"`
	PassSettings ast.Node `yaml:"pass-settings"`

	// FailAction Executed in case no challenges match or
	FailAction   string   `yaml:"fail"`
	FailSettings ast.Node `yaml:"fail-settings"`
}

type Challenge struct {
	RuleHash   string
	Code       int
	Continue   bool
	Challenges []*challenge.Registration

	PassAction Handler
	FailAction Handler
}

func (a Challenge) Handle(logger *slog.Logger, w http.ResponseWriter, r *http.Request, done func() (backend http.Handler)) (next bool, err error) {
	data := challenge.RequestDataFromContext(r.Context())
	for _, reg := range a.Challenges {
		if data.HasValidChallenge(reg.Id()) {
			if a.Continue {
				return true, nil
			}

			// we passed!
			return a.PassAction.Handle(logger.With("challenge", reg.Name), w, r, done)
		}
	}
	// none matched, issue challenges in sequential priority
	for _, reg := range a.Challenges {
		result := data.ChallengeVerify[reg.Id()]
		state := data.ChallengeState[reg.Id()]
		if result.Ok() || result == challenge.VerifyResultSkip || state == challenge.VerifyStatePass {
			// skip already ok'd challenges for some reason (TODO: why)
			// also skip skipped challenges due to preconditions
			continue
		}

		expiry := data.Expiration(reg.Duration)
		key := challenge.GetChallengeKeyForRequest(data.State, reg, expiry, r)
		data.State.ChallengeIssued(r, reg, r.URL.String(), logger)
		result = reg.IssueChallenge(w, r, key, expiry)
		data.ChallengeVerify[reg.Id()] = result
		data.ChallengeState[reg.Id()] = challenge.VerifyStatePass
		switch result {
		case challenge.VerifyResultOK:
			data.State.ChallengePassed(r, reg, r.URL.String(), logger)
			if a.Continue {
				return true, nil
			}

			return a.PassAction.Handle(logger.With("challenge", reg.Name), w, r, done)
		case challenge.VerifyResultNotOK:
			// we have had the challenge checked, but it's not ok!
			// safe to continue
			continue
		case challenge.VerifyResultFail:
			err := fmt.Errorf("challenge %s failed on issuance", reg.Name)
			data.State.ChallengeFailed(r, reg, err, r.URL.String(), logger)

			if reg.Class == challenge.ClassTransparent {
				// allow continuing transparent challenges
				continue
			}

			return a.FailAction.Handle(logger, w, r, done)
		case challenge.VerifyResultNone:
			// challenge was issued
			if reg.Class == challenge.ClassTransparent {
				// allow continuing transparent challenges
				continue
			}
			// we cannot continue after issuance
			return false, nil

		case challenge.VerifyResultSkip:
			// continue onto next one due to precondition
			continue
		}
	}

	// nothing matched, execute default action
	return a.FailAction.Handle(logger, w, r, done)
}
