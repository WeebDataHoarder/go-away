package lib

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"git.gammaspectra.live/git/go-away/lib/action"
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/lib/condition"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"log/slog"
	"net/http"
	"strings"
)

type RuleState struct {
	Name string
	Hash string

	Condition cel.Program

	Action  policy.RuleAction
	Handler action.Handler

	Children []RuleState
}

func NewRuleState(state challenge.StateInterface, r policy.Rule, replacer *strings.Replacer, parent *RuleState) (RuleState, error) {
	fp := sha256.Sum256(state.PrivateKey())
	hasher := sha256.New()
	if parent != nil {
		hasher.Write([]byte(parent.Name))
		hasher.Write([]byte{0})
		r.Name = fmt.Sprintf("%s/%s", parent.Name, r.Name)
	}
	hasher.Write([]byte(r.Name))
	hasher.Write([]byte{0})
	hasher.Write(fp[:])
	sum := hasher.Sum(nil)

	rule := RuleState{
		Name:   r.Name,
		Hash:   hex.EncodeToString(sum[:10]),
		Action: policy.RuleAction(strings.ToUpper(r.Action)),
	}

	newHandler, ok := action.Register[rule.Action]
	if !ok {
		return RuleState{}, fmt.Errorf("unknown action %s", r.Action)
	}

	actionHandler, err := newHandler(state, rule.Name, rule.Hash, r.Settings)
	if err != nil {
		return RuleState{}, err
	}
	rule.Handler = actionHandler

	if len(r.Conditions) > 0 {
		// allow nesting
		var conditions []string
		for _, cond := range r.Conditions {
			cond = replacer.Replace(cond)
			conditions = append(conditions, cond)
		}

		ast, err := condition.FromStrings(state.ProgramEnv(), condition.OperatorOr, conditions...)
		if err != nil {
			return RuleState{}, fmt.Errorf("error compiling conditions: %w", err)
		}

		program, err := condition.Program(state.ProgramEnv(), ast)
		if err != nil {
			return RuleState{}, fmt.Errorf("error compiling program: %w", err)
		}
		rule.Condition = program
	}

	if len(r.Children) > 0 {
		for _, child := range r.Children {
			childRule, err := NewRuleState(state, child, replacer, &rule)
			if err != nil {
				return RuleState{}, fmt.Errorf("child %s: %w", child.Name, err)
			}
			rule.Children = append(rule.Children, childRule)
		}
	}

	return rule, nil
}

func (rule RuleState) Evaluate(logger *slog.Logger, w http.ResponseWriter, r *http.Request, done func() http.Handler) (next bool, err error) {
	data := challenge.RequestDataFromContext(r.Context())
	var out ref.Val

	lg := logger.With("rule", rule.Name, "rule_hash", rule.Hash, "action", string(rule.Action))
	if rule.Condition != nil {
		out, _, err = rule.Condition.Eval(data.ProgramEnv)
	} else {
		// default true
		out = types.Bool(true)
	}
	if err != nil {
		lg.Error(err.Error())
		return false, fmt.Errorf("error: evaluating administrative rule %s/%s: %w", data.Id.String(), rule.Hash, err)
	} else if out != nil && out.Type() == types.BoolType {
		if out.Equal(types.True) == types.True {
			next, err = rule.Handler.Handle(lg, w, r, func() http.Handler {
				r.Header.Set("X-Away-Rule", rule.Name)
				r.Header.Set("X-Away-Hash", rule.Hash)
				r.Header.Set("X-Away-Action", string(rule.Action))

				return done()
			})
			if err != nil {
				lg.Error(err.Error())
				return false, fmt.Errorf("error: executing administrative rule %s/%s: %w", data.Id.String(), rule.Hash, err)
			}

			if !next {
				return next, nil
			}

			for _, child := range rule.Children {
				next, err = child.Evaluate(logger, w, r, done)
				if err != nil {
					lg.Error(err.Error())
					return false, fmt.Errorf("error: executing administrative rule %s/%s: %w", data.Id.String(), rule.Hash, err)
				}

				if !next {
					return next, nil
				}
			}
		}
	}

	return true, nil
}
