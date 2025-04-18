package policy

import (
	"github.com/goccy/go-yaml/ast"
	"time"
)

type Challenge struct {
	Conditions []string `yaml:"conditions"`
	Runtime    string   `yaml:"runtime"`

	Duration time.Duration `yaml:"duration"`

	Parameters ast.Node `yaml:"parameters,omitempty"`
}
