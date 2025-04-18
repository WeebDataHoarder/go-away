package lib

import (
	"codeberg.org/meta/gzipped/v2"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"git.gammaspectra.live/git/go-away/embed"
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/lib/challenge/wasm"
	"git.gammaspectra.live/git/go-away/lib/challenge/wasm/interface"
	"git.gammaspectra.live/git/go-away/lib/condition"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"git.gammaspectra.live/git/go-away/utils"
	"git.gammaspectra.live/git/go-away/utils/inline"
	"github.com/google/cel-go/cel"
	"github.com/tetratelabs/wazero/api"
	"github.com/yl2chen/cidranger"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type State struct {
	Client   *http.Client
	Settings StateSettings
	UrlPath  string
	Mux      *http.ServeMux

	Networks map[string]cidranger.Ranger

	Wasm *wasm.Runner

	Challenges map[challenge.Id]challenge.Challenge

	RulesEnv *cel.Env

	Rules []RuleState

	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey

	Poison map[string][]byte

	ChallengeSolve sync.Map

	DecayMap *utils.DecayMap[[net.IPv6len]byte, utils.DNSBLResponse]

	close chan struct{}
}

func (state *State) AwaitChallenge(key []byte, ctx context.Context) challenge.VerifyResult {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var result atomic.Int64

	state.ChallengeSolve.Store(string(key), ChallengeCallback(func(receivedResult challenge.VerifyResult) {
		result.Store(int64(receivedResult))
		cancel()
	}))

	<-ctx.Done()

	return challenge.VerifyResult(result.Load())
}

func (state *State) SolveChallenge(key []byte, result challenge.VerifyResult) {
	if f, ok := state.ChallengeSolve.LoadAndDelete(string(key)); ok && f != nil {
		if cb, ok := f.(ChallengeCallback); ok {
			cb(result)
		}
	}
}

type ChallengeCallback func(result challenge.VerifyResult)

type RuleState struct {
	Name string
	Hash string

	Host *string

	Program    cel.Program
	Action     policy.RuleAction
	Challenges []challenge.Id
}

type StateSettings struct {
	Backends               map[string]http.Handler
	PrivateKeySeed         []byte
	Debug                  bool
	PackageName            string
	ChallengeTemplate      string
	ChallengeTemplateTheme string
	ClientIpHeader         string
	BackendIpHeader        string
	DNSBL                  *utils.DNSBL
}

func NewState(p policy.Policy, settings StateSettings) (handler http.Handler, err error) {
	state := new(State)
	state.close = make(chan struct{})
	state.Settings = settings
	state.Client = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	state.UrlPath = "/.well-known/." + state.Settings.PackageName

	if state.Settings.DNSBL != nil {
		state.DecayMap = utils.NewDecayMap[[net.IPv6len]byte, utils.DNSBLResponse]()
	}

	// set a reasonable configuration for default http proxy if there is none
	for _, backend := range state.Settings.Backends {
		if proxy, ok := backend.(*httputil.ReverseProxy); ok {
			if proxy.ErrorHandler == nil {
				proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
					state.logger(r).Error(err.Error())
					_ = state.errorPage(w, r.Header.Get("X-Away-Id"), http.StatusBadGateway, err, "")
				}
			}
		}
	}

	if len(state.Settings.PrivateKeySeed) > 0 {
		if len(state.Settings.PrivateKeySeed) != ed25519.SeedSize {
			return nil, fmt.Errorf("invalid private key seed length: %d", len(state.Settings.PrivateKeySeed))
		}

		state.privateKey = ed25519.NewKeyFromSeed(state.Settings.PrivateKeySeed)
		state.publicKey = state.privateKey.Public().(ed25519.PublicKey)

		clear(state.Settings.PrivateKeySeed)

	} else {
		state.publicKey, state.privateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
	}

	privateKeyFingerprint := sha256.Sum256(state.privateKey)

	if state.Settings.ChallengeTemplate == "" {
		state.Settings.ChallengeTemplate = "anubis"
	}

	if templates["challenge-"+state.Settings.ChallengeTemplate+".gohtml"] == nil {

		if data, err := os.ReadFile(state.Settings.ChallengeTemplate); err == nil && len(data) > 0 {
			name := path.Base(state.Settings.ChallengeTemplate)
			err := initTemplate(name, string(data))
			if err != nil {
				return nil, fmt.Errorf("error loading template %s: %w", settings.ChallengeTemplate, err)
			}
			state.Settings.ChallengeTemplate = name
		}

		return nil, fmt.Errorf("no template defined for %s", settings.ChallengeTemplate)
	}

	state.Networks = make(map[string]cidranger.Ranger)
	for k, network := range p.Networks {
		ranger := cidranger.NewPCTrieRanger()
		for _, e := range network {
			if e.Url != nil {
				slog.Debug("loading network url list", "network", k, "url", *e.Url)
			}
			prefixes, err := e.FetchPrefixes(state.Client)
			if err != nil {
				slog.Error("error fetching network url list", "network", k, "url", *e.Url)
				continue
			}
			for _, prefix := range prefixes {
				err = ranger.Insert(cidranger.NewBasicRangerEntry(prefix))
				if err != nil {
					return nil, fmt.Errorf("networks %s: error inserting prefix %s: %v", k, prefix.String(), err)
				}
			}
		}

		slog.Warn("loaded network prefixes", "network", k, "count", ranger.Len())

		state.Networks[k] = ranger
	}

	state.Wasm = wasm.NewRunner(true)

	err = state.initConditions()
	if err != nil {
		return nil, err
	}

	var replacements []string
	for k, entries := range p.Conditions {
		ast, err := condition.FromStrings(state.RulesEnv, condition.OperatorOr, entries...)
		if err != nil {
			return nil, fmt.Errorf("conditions %s: error compiling conditions: %v", k, err)
		}

		cond, err := cel.AstToString(ast)
		if err != nil {
			return nil, fmt.Errorf("conditions %s: error printing condition: %v", k, err)
		}

		replacements = append(replacements, fmt.Sprintf("($%s)", k))
		replacements = append(replacements, "("+cond+")")
	}
	conditionReplacer := strings.NewReplacer(replacements...)

	state.Challenges = make(map[challenge.Id]challenge.Challenge)

	idCounter := challenge.Id(1)

	//TODO: move this to self-contained challenge files
	for challengeName, p := range p.Challenges {

		// allow nesting
		var conditions []string
		for _, cond := range p.Conditions {
			cond = conditionReplacer.Replace(cond)
			conditions = append(conditions, cond)
		}

		var program cel.Program
		if len(conditions) > 0 {
			ast, err := condition.FromStrings(state.RulesEnv, condition.OperatorOr, conditions...)
			if err != nil {
				return nil, fmt.Errorf("challenge %s: error compiling conditions: %v", challengeName, err)
			}
			program, err = state.RulesEnv.Program(ast)
			if err != nil {
				return nil, fmt.Errorf("challenge %s: error compiling program: %v", challengeName, err)
			}
		}

		c := challenge.Challenge{
			Id:                idCounter,
			Program:           program,
			Name:              challengeName,
			Path:              fmt.Sprintf("%s/challenge/%s", state.UrlPath, challengeName),
			VerifyProbability: p.Runtime.Probability,
		}
		idCounter++

		if c.VerifyProbability <= 0 {
			//10% default
			c.VerifyProbability = 0.1
		} else if c.VerifyProbability > 1.0 {
			c.VerifyProbability = 1.0
		}

		assetPath := c.Path + "/static/"
		subFs, err := fs.Sub(embed.ChallengeFs, fmt.Sprintf("challenge/%s/static", challengeName))
		if err == nil {
			c.ServeStatic = http.StripPrefix(
				assetPath,
				gzipped.FileServer(gzipped.FS(subFs)),
			)
		}

		switch p.Mode {
		default:
			return nil, fmt.Errorf("unknown challenge mode: %s", p.Mode)
		case "http":
			if p.Url == nil {
				return nil, fmt.Errorf("challenge %s: missing url", challengeName)
			}
			method := p.Parameters["http-method"]
			if method == "" {
				method = "GET"
			}

			httpCode, _ := strconv.Atoi(p.Parameters["http-code"])
			if httpCode == 0 {
				httpCode = http.StatusOK
			}

			expectedCookie := p.Parameters["http-cookie"]

			c.Verify = func(key []byte, result string, r *http.Request) (bool, error) {
				var cookieValue string
				if expectedCookie != "" {
					if cookie, err := r.Cookie(expectedCookie); err != nil || cookie == nil {
						// skip check if we don't have cookie or it's expired
						return false, nil
					} else {
						cookieValue = cookie.Value
					}
				}
				// bind hash of cookie contents
				sum := sha256.New()
				sum.Write([]byte(cookieValue))
				sum.Write([]byte{0})
				sum.Write(key)
				sum.Write([]byte{0})
				sum.Write(state.publicKey)

				if subtle.ConstantTimeCompare(sum.Sum(nil), []byte(result)) == 1 {
					return true, nil
				}
				return false, nil
			}

			c.ServeChallenge = func(w http.ResponseWriter, r *http.Request, key []byte, expiry time.Time) challenge.Result {

				data := RequestDataFromContext(r.Context())

				if result := data.Challenges[c.Id]; result.Ok() {
					return challenge.ResultPass
				}

				var cookieValue string
				if expectedCookie != "" {
					if cookie, err := r.Cookie(expectedCookie); err != nil || cookie == nil {
						// skip check if we don't have cookie or it's expired
						return challenge.ResultContinue
					} else {
						cookieValue = cookie.Value
					}
				}

				request, err := http.NewRequest(method, *p.Url, nil)
				if err != nil {
					return challenge.ResultContinue
				}

				request.Header = r.Header
				response, err := state.Client.Do(request)
				if err != nil {
					return challenge.ResultContinue
				}
				defer response.Body.Close()
				defer io.Copy(io.Discard, response.Body)

				if response.StatusCode != httpCode {
					utils.ClearCookie(utils.CookiePrefix+c.Name, w)
					// continue other challenges!

					//TODO: negatively cache failure

					return challenge.ResultContinue
				} else {
					// bind hash of cookie contents
					sum := sha256.New()
					sum.Write([]byte(cookieValue))
					sum.Write([]byte{0})
					sum.Write(key)
					sum.Write([]byte{0})
					sum.Write(state.publicKey)
					token, err := c.IssueChallengeToken(state.privateKey, key, sum.Sum(nil), expiry)
					if err != nil {
						utils.ClearCookie(utils.CookiePrefix+c.Name, w)
					} else {
						utils.SetCookie(utils.CookiePrefix+challengeName, token, expiry, w)
					}

					data.Challenges[c.Id] = challenge.VerifyResultPASS

					// we passed it!
					return challenge.ResultPass
				}
			}

		case "cookie":
			c.ServeChallenge = func(w http.ResponseWriter, r *http.Request, key []byte, expiry time.Time) challenge.Result {
				if chall := r.URL.Query().Get("__goaway_challenge"); chall == challengeName {
					state.logger(r).Warn("challenge failed", "challenge", c.Name)
					utils.ClearCookie(utils.CookiePrefix+c.Name, w)
					_ = state.errorPage(w, r.Header.Get("X-Away-Id"), http.StatusForbidden, fmt.Errorf("access denied: failed challenge %s", c.Name), "")
					return challenge.ResultStop
				}

				token, err := c.IssueChallengeToken(state.privateKey, key, nil, expiry)
				if err != nil {
					utils.ClearCookie(utils.CookiePrefix+challengeName, w)
				} else {
					utils.SetCookie(utils.CookiePrefix+challengeName, token, expiry, w)
				}

				// self redirect!
				uri, err := url.ParseRequestURI(r.URL.String())
				values := uri.Query()
				values.Set("__goaway_challenge", challengeName)
				uri.RawQuery = values.Encode()

				http.Redirect(w, r, uri.String(), http.StatusTemporaryRedirect)
				return challenge.ResultStop
			}
		case "meta-refresh":
			c.ServeChallenge = func(w http.ResponseWriter, r *http.Request, key []byte, expiry time.Time) challenge.Result {
				redirectUri := new(url.URL)
				redirectUri.Path = c.Path + "/verify-challenge"

				values := make(url.Values)
				values.Set("result", hex.EncodeToString(key))
				values.Set("redirect", r.URL.String())
				values.Set("requestId", r.Header.Get("X-Away-Id"))

				redirectUri.RawQuery = values.Encode()

				_ = state.challengePage(w, r.Header.Get("X-Away-Id"), http.StatusTeapot, "", map[string]any{
					"Meta": map[string]string{
						"refresh": "0; url=" + redirectUri.String(),
					},
				})

				return challenge.ResultStop
			}
		case "header-refresh":
			c.ServeChallenge = func(w http.ResponseWriter, r *http.Request, key []byte, expiry time.Time) challenge.Result {
				redirectUri := new(url.URL)
				redirectUri.Path = c.Path + "/verify-challenge"

				values := make(url.Values)
				values.Set("result", hex.EncodeToString(key))
				values.Set("redirect", r.URL.String())
				values.Set("requestId", r.Header.Get("X-Away-Id"))

				redirectUri.RawQuery = values.Encode()

				// self redirect!
				w.Header().Set("Refresh", "0; url="+redirectUri.String())

				_ = state.challengePage(w, r.Header.Get("X-Away-Id"), http.StatusTeapot, "", nil)

				return challenge.ResultStop
			}
		case "preload-link":
			deadline, _ := time.ParseDuration(p.Parameters["preload-early-hint-deadline"])
			if deadline == 0 {
				deadline = time.Second * 3
			}

			c.ServeChallenge = func(w http.ResponseWriter, r *http.Request, key []byte, expiry time.Time) challenge.Result {
				// this only works on HTTP/2 and HTTP/3

				if r.ProtoMajor < 2 {
					// this can happen if we are an upgraded request from HTTP/1.1 to HTTP/2 in H2C
					if _, ok := w.(http.Pusher); !ok {
						return challenge.ResultContinue
					}
				}

				data := RequestDataFromContext(r.Context())
				redirectUri := new(url.URL)
				redirectUri.Scheme = getRequestScheme(r)
				redirectUri.Host = r.Host
				redirectUri.Path = c.Path + "/verify-challenge"

				values := make(url.Values)
				values.Set("result", hex.EncodeToString(key))
				values.Set("requestId", r.Header.Get("X-Away-Id"))

				redirectUri.RawQuery = values.Encode()

				w.Header().Set("Link", fmt.Sprintf("<%s>; rel=\"preload\"; as=\"style\"; fetchpriority=high", redirectUri.String()))
				defer func() {
					// remove old header so it won't show on response!
					w.Header().Del("Link")
				}()
				w.WriteHeader(http.StatusEarlyHints)

				ctx, cancel := context.WithTimeout(r.Context(), deadline)
				defer cancel()
				if result := state.AwaitChallenge(key, ctx); result.Ok() {
					data.Challenges[c.Id] = challenge.VerifyResultPASS

					// this should serve!
					return challenge.ResultPass
				}

				data.Challenges[c.Id] = challenge.VerifyResultFAIL
				// we failed, continue
				return challenge.ResultContinue
			}
		case "resource-load":
			c.ServeChallenge = func(w http.ResponseWriter, r *http.Request, key []byte, expiry time.Time) challenge.Result {
				redirectUri := new(url.URL)
				redirectUri.Path = c.Path + "/verify-challenge"

				values := make(url.Values)
				values.Set("result", hex.EncodeToString(key))
				values.Set("requestId", r.Header.Get("X-Away-Id"))

				redirectUri.RawQuery = values.Encode()

				// self redirect!
				w.Header().Set("Refresh", "2; url="+r.URL.String())

				_ = state.challengePage(w, r.Header.Get("X-Away-Id"), http.StatusTeapot, "", map[string]any{
					"Tags": []template.HTML{
						template.HTML(fmt.Sprintf("<link href=\"%s\" rel=\"stylesheet\" crossorigin=\"use-credentials\">", redirectUri.String())),
					},
				})

				return challenge.ResultStop
			}
		case "js":
			c.ServeChallenge = func(w http.ResponseWriter, r *http.Request, key []byte, expiry time.Time) challenge.Result {
				_ = state.challengePage(w, r.Header.Get("X-Away-Id"), http.StatusTeapot, challengeName, nil)

				return challenge.ResultStop
			}
			c.ServeScriptPath = c.Path + "/challenge.mjs"
			c.ServeScript = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				params, _ := json.Marshal(p.Parameters)

				//TODO: move this to http.go as a template
				w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
				w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
				w.WriteHeader(http.StatusOK)

				err := templates["challenge.mjs"].Execute(w, map[string]any{
					"Path":       c.Path,
					"Parameters": string(params),
					"Random":     cacheBust,
					"Challenge":  challengeName,
					"ChallengeScript": func() string {
						if p.Asset != nil {
							return assetPath + *p.Asset
						} else if p.Url != nil {
							return *p.Url
						} else {
							panic("not implemented")
						}
					}(),
				})
				if err != nil {
					//TODO: log
				}
			})
		}

		// how to runtime
		switch p.Runtime.Mode {
		default:
			return nil, fmt.Errorf("unknown challenge runtime mode: %s", p.Runtime.Mode)
		case "":
		case "http":
		case "key":
			mimeType := p.Parameters["key-mime"]
			if mimeType == "" {
				mimeType = "text/html; charset=utf-8"
			}

			httpCode, _ := strconv.Atoi(p.Parameters["key-code"])
			if httpCode == 0 {
				httpCode = http.StatusTemporaryRedirect
			}

			var content []byte
			if data, ok := p.Parameters["key-content"]; ok {
				content = []byte(data)
			}

			c.Verify = func(key []byte, result string, r *http.Request) (bool, error) {
				resultBytes, err := hex.DecodeString(result)
				if err != nil {
					return false, err
				}

				if subtle.ConstantTimeCompare(resultBytes, key) != 1 {
					return false, nil
				}
				return true, nil
			}

			c.ServeVerifyChallenge = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

				redirect, err := utils.EnsureNoOpenRedirect(r.FormValue("redirect"))
				if err != nil {
					_ = state.errorPage(w, r.Header.Get("X-Away-Id"), http.StatusBadRequest, err, "")
					return
				}

				err = func() (err error) {

					data := RequestDataFromContext(r.Context())

					key := state.GetChallengeKeyForRequest(challengeName, data.Expires, r)
					result := r.FormValue("result")

					requestId, err := hex.DecodeString(r.FormValue("requestId"))
					if err == nil {
						r.Header.Set("X-Away-Id", hex.EncodeToString(requestId))
					}

					if ok, err := c.Verify(key, result, r); err != nil {
						return err
					} else if !ok {
						utils.ClearCookie(utils.CookiePrefix+challengeName, w)
						data.Challenges[c.Id] = challenge.VerifyResultFAIL
						state.SolveChallenge(key, challenge.VerifyResultFAIL)
						state.logger(r).Warn("challenge failed", "challenge", challengeName, "redirect", redirect)

						// catch happy eyeballs IPv4 -> IPv6 migration, re-direct to try again
						if resultKey, err := ChallengeKeyFromString(result); err == nil && resultKey.Get(ChallengeKeyFlagIsIPv4) > 0 && key.Get(ChallengeKeyFlagIsIPv4) == 0 {

						} else {
							_ = state.errorPage(w, r.Header.Get("X-Away-Id"), http.StatusForbidden, fmt.Errorf("access denied: failed challenge %s", challengeName), redirect)
							return nil
						}
					} else {
						state.logger(r).Warn("challenge passed", "challenge", challengeName, "redirect", redirect)

						token, err := c.IssueChallengeToken(state.privateKey, key, []byte(result), data.Expires)
						if err != nil {
							utils.ClearCookie(utils.CookiePrefix+challengeName, w)
						} else {
							utils.SetCookie(utils.CookiePrefix+challengeName, token, data.Expires, w)
						}
						data.Challenges[c.Id] = challenge.VerifyResultPASS
						state.SolveChallenge(key, challenge.VerifyResultPASS)
					}

					switch httpCode {
					case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
						if redirect == "" {
							_ = state.errorPage(w, r.Header.Get("X-Away-Id"), http.StatusBadRequest, errors.New("no redirect found"), "")
							return nil
						}
						http.Redirect(w, r, redirect, httpCode)
					default:
						w.Header().Set("Content-Type", mimeType)
						w.WriteHeader(httpCode)
						if content != nil {
							_, _ = w.Write(content)
						}
					}

					return nil
				}()
				if err != nil {
					utils.ClearCookie(utils.CookiePrefix+challengeName, w)
					_ = state.errorPage(w, r.Header.Get("X-Away-Id"), http.StatusInternalServerError, err, redirect)
					return
				}
			})

		case "wasm":
			wasmData, err := embed.ChallengeFs.ReadFile(fmt.Sprintf("challenge/%s/runtime/%s", challengeName, p.Runtime.Asset))
			if err != nil {
				return nil, fmt.Errorf("c %s: could not load runtime: %w", challengeName, err)
			}
			err = state.Wasm.Compile(challengeName, wasmData)
			if err != nil {
				return nil, fmt.Errorf("c %s: compiling runtime: %w", challengeName, err)
			}

			c.ServeMakeChallenge = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				err := state.Wasm.Instantiate(challengeName, func(ctx context.Context, mod api.Module) (err error) {

					data := RequestDataFromContext(r.Context())

					in := _interface.MakeChallengeInput{
						Key:        state.GetChallengeKeyForRequest(challengeName, data.Expires, r),
						Parameters: p.Parameters,
						Headers:    inline.MIMEHeader(r.Header),
					}
					in.Data, err = io.ReadAll(r.Body)
					if err != nil {
						return err
					}

					out, err := wasm.MakeChallengeCall(ctx, mod, in)
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
					_ = state.errorPage(w, r.Header.Get("X-Away-Id"), http.StatusInternalServerError, err, "")
					return
				}
			})

			c.Verify = func(key []byte, result string, r *http.Request) (ok bool, err error) {
				err = state.Wasm.Instantiate(challengeName, func(ctx context.Context, mod api.Module) (err error) {
					in := _interface.VerifyChallengeInput{
						Key:        key,
						Parameters: p.Parameters,
						Result:     []byte(result),
					}

					out, err := wasm.VerifyChallengeCall(ctx, mod, in)
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
					return false, err
				}
				return ok, nil
			}
		}

		state.Challenges[c.Id] = c
	}

	for _, rule := range p.Rules {
		hasher := sha256.New()
		hasher.Write([]byte(rule.Name))
		hasher.Write([]byte{0})
		if rule.Host != nil {
			hasher.Write([]byte(*rule.Host))
		}
		hasher.Write([]byte{0})
		hasher.Write(privateKeyFingerprint[:])
		sum := hasher.Sum(nil)

		challenges := make([]challenge.Id, 0, len(rule.Challenges))

		for _, challengeName := range rule.Challenges {
			c, ok := state.GetChallengeByName(challengeName)
			if !ok {
				return nil, fmt.Errorf("challenge %s not found", challengeName)
			}
			challenges = append(challenges, c.Id)
		}

		r := RuleState{
			Name:       rule.Name,
			Hash:       hex.EncodeToString(sum[:8]),
			Host:       rule.Host,
			Action:     policy.RuleAction(strings.ToUpper(rule.Action)),
			Challenges: challenges,
		}

		if (r.Action == policy.RuleActionCHALLENGE || r.Action == policy.RuleActionCHECK) && len(r.Challenges) == 0 {
			return nil, fmt.Errorf("no challenges found in rule %s", rule.Name)
		}

		// allow nesting
		var conditions []string
		for _, cond := range rule.Conditions {
			cond = conditionReplacer.Replace(cond)
			conditions = append(conditions, cond)
		}

		ast, err := condition.FromStrings(state.RulesEnv, condition.OperatorOr, conditions...)
		if err != nil {
			return nil, fmt.Errorf("rules %s: error compiling conditions: %v", rule.Name, err)
		}
		program, err := state.RulesEnv.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("rules %s: error compiling program: %v", rule.Name, err)
		}
		r.Program = program

		slog.Warn("loaded rule", "rule", r.Name, "hash", r.Hash, "action", rule.Action)

		state.Rules = append(state.Rules, r)
	}

	state.Mux = http.NewServeMux()

	if err = state.setupRoutes(); err != nil {
		return nil, err
	}

	if state.DecayMap != nil {
		go func() {
			ticker := time.NewTicker(17 * time.Minute)
			for {
				select {
				case <-ticker.C:
					state.DecayMap.Decay()
				case <-state.close:
					return
				}
			}
		}()
	}

	return state, nil
}

func (state *State) GetChallengeByName(name string) (challenge.Challenge, bool) {
	for _, c := range state.Challenges {
		if c.Name == name {
			return c, true
		}
	}
	return challenge.Challenge{}, false
}
