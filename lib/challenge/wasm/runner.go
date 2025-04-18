package wasm

import (
	"context"
	"errors"
	"fmt"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"slices"
)

type Runner struct {
	context context.Context
	runtime wazero.Runtime

	modules map[string]wazero.CompiledModule
}

func NewRunner(useNativeCompiler bool) *Runner {
	var r Runner
	r.context = context.Background()
	var runtimeConfig wazero.RuntimeConfig
	if useNativeCompiler {
		runtimeConfig = wazero.NewRuntimeConfigCompiler()
	} else {
		runtimeConfig = wazero.NewRuntimeConfigInterpreter()
	}
	r.runtime = wazero.NewRuntimeWithConfig(r.context, runtimeConfig)
	wasi_snapshot_preview1.MustInstantiate(r.context, r.runtime)

	r.modules = make(map[string]wazero.CompiledModule)

	return &r
}

func (r *Runner) Compile(key string, binary []byte) error {
	module, err := r.runtime.CompileModule(r.context, binary)
	if err != nil {
		return err
	}

	// check interface
	functions := module.ExportedFunctions()
	if f, ok := functions["MakeChallenge"]; ok {
		if slices.Compare(f.ParamTypes(), []api.ValueType{api.ValueTypeI64}) != 0 {
			return fmt.Errorf("MakeChallenge does not follow parameter interface")
		}
		if slices.Compare(f.ResultTypes(), []api.ValueType{api.ValueTypeI64}) != 0 {
			return fmt.Errorf("MakeChallenge does not follow result interface")
		}
	} else {
		module.Close(r.context)
		return errors.New("no MakeChallenge exported")
	}

	if f, ok := functions["VerifyChallenge"]; ok {
		if slices.Compare(f.ParamTypes(), []api.ValueType{api.ValueTypeI64}) != 0 {
			return fmt.Errorf("VerifyChallenge does not follow parameter interface")
		}
		if slices.Compare(f.ResultTypes(), []api.ValueType{api.ValueTypeI64}) != 0 {
			return fmt.Errorf("VerifyChallenge does not follow result interface")
		}
	} else {
		module.Close(r.context)
		return errors.New("no VerifyChallenge exported")
	}

	if f, ok := functions["malloc"]; ok {
		if slices.Compare(f.ParamTypes(), []api.ValueType{api.ValueTypeI32}) != 0 {
			return fmt.Errorf("malloc does not follow parameter interface")
		}
		if slices.Compare(f.ResultTypes(), []api.ValueType{api.ValueTypeI32}) != 0 {
			return fmt.Errorf("malloc does not follow result interface")
		}
	} else {
		module.Close(r.context)
		return errors.New("no malloc exported")
	}

	if f, ok := functions["free"]; ok {
		if slices.Compare(f.ParamTypes(), []api.ValueType{api.ValueTypeI32}) != 0 {
			return fmt.Errorf("free does not follow parameter interface")
		}
		if slices.Compare(f.ResultTypes(), []api.ValueType{}) != 0 {
			return fmt.Errorf("free does not follow result interface")
		}
	} else {
		module.Close(r.context)
		return errors.New("no free exported")
	}

	r.modules[key] = module
	return nil
}

func (r *Runner) Close() error {
	for _, module := range r.modules {
		if err := module.Close(r.context); err != nil {
			return err
		}
	}
	return r.runtime.Close(r.context)
}

var ErrModuleNotFound = errors.New("module not found")

func (r *Runner) Instantiate(key string, f func(ctx context.Context, mod api.Module) error) (err error) {
	compiledModule, ok := r.modules[key]
	if !ok {
		return ErrModuleNotFound
	}
	mod, err := r.runtime.InstantiateModule(
		r.context,
		compiledModule,
		wazero.NewModuleConfig().WithName(key).WithStartFunctions("_initialize"),
	)
	if err != nil {
		return err
	}
	defer mod.Close(r.context)

	return f(r.context, mod)
}
