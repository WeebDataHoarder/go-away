package lib

import (
	http_cel "codeberg.org/gone/http-cel"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"git.gammaspectra.live/git/go-away/lib/settings"
	"git.gammaspectra.live/git/go-away/utils"
	"github.com/google/cel-go/cel"
	"github.com/yl2chen/cidranger"
	"golang.org/x/net/html"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

type State struct {
	client  *http.Client
	radb    *utils.RADb
	urlPath string

	programEnv *cel.Env

	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey

	opt      settings.Settings
	settings policy.StateSettings

	networks map[string]cidranger.Ranger

	challenges challenge.Register

	rules []RuleState

	close chan struct{}

	tagCache *utils.DecayMap[string, []html.Node]

	Mux *http.ServeMux
}

func NewState(p policy.Policy, opt settings.Settings, settings policy.StateSettings) (handler http.Handler, err error) {
	state := new(State)
	state.close = make(chan struct{})
	state.settings = settings
	state.opt = opt
	metrics.Reset()
	state.client = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	state.radb, err = utils.NewRADb()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize RADb client: %w", err)
	}

	state.urlPath = state.Settings().BasePath

	// set a reasonable configuration for default http proxy if there is none
	for _, backend := range state.Settings().Backends {
		if proxy, ok := backend.(*httputil.ReverseProxy); ok {
			if proxy.ErrorHandler == nil {
				proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
					state.Logger(r).Error(err.Error())
					state.ErrorPage(w, r, http.StatusBadGateway, err, "")
				}
			}
		}
	}

	if len(state.Settings().PrivateKeySeed) > 0 {
		if len(state.Settings().PrivateKeySeed) != ed25519.SeedSize {
			return nil, fmt.Errorf("invalid private key seed length: %d", len(state.Settings().PrivateKeySeed))
		}

		state.privateKey = ed25519.NewKeyFromSeed(state.Settings().PrivateKeySeed)
		state.publicKey = state.privateKey.Public().(ed25519.PublicKey)

		clear(state.settings.PrivateKeySeed)

	} else {
		state.publicKey, state.privateKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
	}

	if templates["challenge-"+state.Options().ChallengeTemplate+".gohtml"] == nil {

		if data, err := os.ReadFile(state.Options().ChallengeTemplate); err == nil && len(data) > 0 {
			name := path.Base(state.Options().ChallengeTemplate)
			err := initTemplate(name, string(data))
			if err != nil {
				return nil, fmt.Errorf("error loading template %s: %w", state.Options().ChallengeTemplate, err)
			}
			state.opt.ChallengeTemplate = name
		}

		return nil, fmt.Errorf("no template defined for %s", state.Options().ChallengeTemplate)
	}

	state.networks = make(map[string]cidranger.Ranger)

	networkCache := utils.CachePrefix(state.Settings().Cache, "networks/")

	for k, network := range p.Networks {

		ranger := cidranger.NewPCTrieRanger()
		for i, e := range network {
			prefixes, err := func() ([]net.IPNet, error) {
				var useCache bool

				cacheKey := fmt.Sprintf("%s-%d-", k, i)
				if e.Url != nil {
					slog.Debug("loading network url list", "network", k, "url", *e.Url)
					useCache = true
					sum := sha256.Sum256([]byte(*e.Url))
					cacheKey += hex.EncodeToString(sum[:4])
				} else if e.ASN != nil {
					slog.Debug("loading ASN", "network", k, "asn", *e.ASN)
					useCache = true
					cacheKey += strconv.FormatInt(int64(*e.ASN), 10)
				}

				var cached []net.IPNet
				if useCache && networkCache != nil {
					//TODO: add randomness
					cachedData, err := networkCache.Get(cacheKey, time.Hour*24)
					var l []string
					_ = json.Unmarshal(cachedData, &l)
					for _, n := range l {
						_, ipNet, err := net.ParseCIDR(n)
						if err == nil {
							cached = append(cached, *ipNet)
						}
					}
					if err == nil {
						// use
						return cached, nil

					}
				}

				prefixes, err := e.FetchPrefixes(state.client, state.radb)
				if err != nil {
					if len(cached) > 0 {
						// use cached meanwhile
						return cached, err
					}
					return nil, err
				}
				if useCache && networkCache != nil {
					var l []string
					for _, n := range prefixes {
						l = append(l, n.String())
					}
					cachedData, err := json.Marshal(l)
					if err == nil {
						_ = networkCache.Set(cacheKey, cachedData)
					}
				}
				return prefixes, nil
			}()
			if err != nil {
				if e.Url != nil {
					slog.Error("error loading network list", "network", k, "url", *e.Url, "error", err)
				} else if e.ASN != nil {
					slog.Error("error loading ASN", "network", k, "asn", *e.ASN, "error", err)
				} else {
					slog.Error("error loading list", "network", k, "error", err)
				}
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

		state.networks[k] = ranger
	}

	err = state.initConditions()
	if err != nil {
		return nil, err
	}

	var replacements []string
	for k, entries := range p.Conditions {
		ast, err := http_cel.NewAst(state.programEnv, http_cel.OperatorOr, entries...)
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

	state.challenges = make(challenge.Register)

	//TODO: move this to self-contained challenge files
	for challengeName, pol := range p.Challenges {
		_, _, err := state.challenges.Create(state, challengeName, pol, conditionReplacer)
		if err != nil {
			return nil, fmt.Errorf("challenge %s: %w", challengeName, err)
		}
	}

	for _, r := range p.Rules {
		rule, err := NewRuleState(state, r, conditionReplacer, nil)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.Name, err)
		}

		slog.Warn("loaded rule", "rule", rule.Name, "hash", rule.Hash, "action", rule.Action, "children", len(rule.Children))

		state.rules = append(state.rules, rule)
	}

	state.Mux = http.NewServeMux()

	if err = state.setupRoutes(); err != nil {
		return nil, err
	}

	state.tagCache = utils.NewDecayMap[string, []html.Node]()

	go func() {
		ticker := time.NewTicker(time.Minute * 37)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				state.tagCache.Decay()
			case <-state.close:
				return
			}
		}
	}()

	return state, nil
}
