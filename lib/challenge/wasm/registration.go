package wasm

import (
	"codeberg.org/meta/gzipped/v2"
	"context"
	"errors"
	"fmt"
	"git.gammaspectra.live/git/go-away/embed"
	"git.gammaspectra.live/git/go-away/lib/challenge"
	_interface "git.gammaspectra.live/git/go-away/lib/challenge/wasm/interface"
	"git.gammaspectra.live/git/go-away/utils"
	"git.gammaspectra.live/git/go-away/utils/inline"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/tetratelabs/wazero/api"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"path"
	"time"
)

func init() {
	challenge.Runtimes["js"] = FillJavaScriptRegistration
}

type Parameters struct {
	Path string `yaml:"path"`
	// Loader path to js/mjs file to use as challenge issuer
	Loader string `yaml:"js-loader"`

	// Runtime path to WASM wasip1 runtime
	Runtime string `yaml:"wasm-runtime"`

	Settings map[string]string `yaml:"wasm-runtime-settings"`

	NativeCompiler bool `yaml:"wasm-native-compiler"`

	VerifyProbability float64 `yaml:"verify-probability"`
}

var DefaultParameters = Parameters{
	VerifyProbability: 0.1,
	NativeCompiler:    true,
}

func FillJavaScriptRegistration(state challenge.StateInterface, reg *challenge.Registration, parameters ast.Node) error {
	params := DefaultParameters

	if parameters != nil {
		ymlData, err := parameters.MarshalYAML()
		if err != nil {
			return err
		}
		err = yaml.Unmarshal(ymlData, &params)
		if err != nil {
			return err
		}
	}

	reg.Class = challenge.ClassBlocking

	mux := http.NewServeMux()

	if params.Path == "" {
		params.Path = reg.Name
	}

	assetsFs, err := embed.GetFallbackFS(embed.ChallengeFs, params.Path)
	if err != nil {
		return err
	}

	if params.VerifyProbability <= 0 {
		//10% default
		params.VerifyProbability = 0.1
	} else if params.VerifyProbability > 1.0 {
		params.VerifyProbability = 1.0
	}

	reg.VerifyProbability = params.VerifyProbability

	ob := NewRunner(params.NativeCompiler)
	reg.Object = ob

	wasmData, err := assetsFs.ReadFile(path.Join("runtime", params.Runtime))
	if err != nil {
		return fmt.Errorf("could not load runtime: %w", err)
	}

	err = ob.Compile("runtime", wasmData)
	if err != nil {
		return fmt.Errorf("compiling runtime: %w", err)
	}

	reg.IssueChallenge = func(w http.ResponseWriter, r *http.Request, key challenge.Key, expiry time.Time) challenge.VerifyResult {
		state.ChallengePage(w, r, state.Settings().ChallengeResponseCode, reg, map[string]any{
			"EndTags": []template.HTML{
				template.HTML(fmt.Sprintf("<script async type=\"module\" src=\"%s?cacheBust=%s\"></script>", reg.Path+"/script.mjs", utils.CacheBust())),
			},
		})
		return challenge.VerifyResultNone
	}

	reg.Verify = func(key challenge.Key, token []byte, r *http.Request) (challenge.VerifyResult, error) {
		var ok bool
		err = ob.Instantiate("runtime", func(ctx context.Context, mod api.Module) (err error) {
			in := _interface.VerifyChallengeInput{
				Key:        key[:],
				Parameters: params.Settings,
				Result:     token,
			}

			out, err := VerifyChallengeCall(ctx, mod, in)
			if err != nil {
				return err
			}

			if out == _interface.VerifyChallengeOutputError {
				return errors.New("error checking challenge")
			}
			ok = out == _interface.VerifyChallengeOutputOK
			return nil
		})
		if err != nil {
			return challenge.VerifyResultFail, err
		}
		if ok {
			return challenge.VerifyResultOK, nil
		}
		return challenge.VerifyResultFail, nil
	}

	// serve assets if existent
	if staticFs, err := fs.Sub(assetsFs, "static"); err != nil {
		return fmt.Errorf("no static assets: %w", err)
	} else {
		mux.Handle("GET "+reg.Path+"/static/", http.StripPrefix(reg.Path+"/static/", gzipped.FileServer(gzipped.FS(staticFs))))
	}

	mux.HandleFunc(reg.Path+challenge.MakeChallengeUrlSuffix, func(w http.ResponseWriter, r *http.Request) {
		data := challenge.RequestDataFromContext(r.Context())
		err := ob.Instantiate("runtime", func(ctx context.Context, mod api.Module) (err error) {
			key := challenge.GetChallengeKeyForRequest(state, reg, data.Expiration(reg.Duration), r)

			in := _interface.MakeChallengeInput{
				Key:        key[:],
				Parameters: params.Settings,
				Headers:    inline.MIMEHeader(r.Header),
			}
			in.Data, err = io.ReadAll(r.Body)
			if err != nil {
				return err
			}

			out, err := MakeChallengeCall(ctx, mod, in)
			if err != nil {
				return err
			}

			// set output headers
			for k, v := range out.Headers {
				w.Header()[k] = v
			}
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(out.Data)))
			w.WriteHeader(out.Code)
			_, _ = w.Write(out.Data)
			return nil
		})
		if err != nil {
			state.ErrorPage(w, r, http.StatusInternalServerError, err, "")
			return
		}
	})

	mux.HandleFunc(reg.Path+challenge.VerifyChallengeUrlSuffix, challenge.VerifyHandlerFunc(state, reg, nil, nil))

	mux.HandleFunc("GET "+reg.Path+"/script.mjs", func(w http.ResponseWriter, r *http.Request) {
		challenge.ServeChallengeScript(w, r, reg, params.Settings, path.Join(reg.Path, "static", params.Loader))
	})

	reg.Handler = mux

	return nil
}
