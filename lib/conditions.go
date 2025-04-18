package lib

import (
	"git.gammaspectra.live/git/go-away/lib/condition"
)

func (state *State) initConditions() (err error) {
	state.programEnv, err = condition.NewRulesEnvironment(state.networks)
	if err != nil {
		return err
	}
	return nil
}
