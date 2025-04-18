package policy

import "github.com/goccy/go-yaml/ast"

type RuleAction string

const (
	// RuleActionNONE Does nothing. Useful for parent rules when children want to be specified
	RuleActionNONE RuleAction = "NONE"
	// RuleActionPASS Passes the connection immediately
	RuleActionPASS RuleAction = "PASS"
	// RuleActionDENY Denies the connection with a fancy page
	RuleActionDENY RuleAction = "DENY"
	// RuleActionBLOCK Denies the connection with a response code
	RuleActionBLOCK RuleAction = "BLOCK"

	// RuleActionDROP Drops the connection without sending a reply
	RuleActionDROP RuleAction = "DROP"

	// RuleActionCHALLENGE Issues a challenge that when passed, passes the connection
	RuleActionCHALLENGE RuleAction = "CHALLENGE"
	// RuleActionCHECK Issues a challenge that when passed, continues checking rules
	RuleActionCHECK RuleAction = "CHECK"

	// RuleActionPROXY Proxies request to a backend, with optional path replacements
	RuleActionPROXY RuleAction = "PROXY"
)

type Rule struct {
	Name       string   `yaml:"name"`
	Conditions []string `yaml:"conditions"`

	Action string `yaml:"action"`

	Settings ast.Node `yaml:"settings"`

	Children []Rule `yaml:"children"`
}
