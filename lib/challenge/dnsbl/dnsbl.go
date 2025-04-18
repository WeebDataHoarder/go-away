package http

import (
	"context"
	"errors"
	"git.gammaspectra.live/git/go-away/lib/challenge"
	"git.gammaspectra.live/git/go-away/utils"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"net"
	"net/http"
	"time"
)

func init() {
	challenge.Runtimes[Key] = FillRegistration
}

const Key = "dnsbl"

type Parameters struct {
	VerifyProbability float64       `yaml:"verify-probability"`
	Host              string        `yaml:"dnsbl-host"`
	Timeout           time.Duration `yaml:"dnsbl-timeout"`
	Decay             time.Duration `yaml:"dnsbl-decay"`
}

var DefaultParameters = Parameters{
	VerifyProbability: 0.10,
	Timeout:           time.Second * 1,
	Decay:             time.Hour * 1,
	Host:              "dnsbl.dronebl.org",
}

func lookup(ctx context.Context, decay, timeout time.Duration, dnsbl *utils.DNSBL, decayMap *utils.DecayMap[[net.IPv6len]byte, utils.DNSBLResponse], ip net.IP) (utils.DNSBLResponse, error) {
	var key [net.IPv6len]byte
	copy(key[:], ip.To16())

	result, ok := decayMap.Get(key)
	if ok {
		return result, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	result, err := dnsbl.Lookup(ctx, ip)
	if err != nil {

	}
	decayMap.Set(key, result, decay)

	return result, err
}

type closer chan struct{}

func (c closer) Close() error {
	select {
	case <-c:
	default:
		close(c)
	}
	return nil
}

func FillRegistration(state challenge.StateInterface, reg *challenge.Registration, parameters ast.Node) error {
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

	if params.Host == "" {
		return errors.New("empty host")
	}

	reg.Class = challenge.ClassTransparent

	if params.VerifyProbability <= 0 {
		//20% default
		params.VerifyProbability = 0.20
	} else if params.VerifyProbability > 1.0 {
		params.VerifyProbability = 1.0
	}
	reg.VerifyProbability = params.VerifyProbability

	decayMap := utils.NewDecayMap[[net.IPv6len]byte, utils.DNSBLResponse]()

	dnsbl := utils.NewDNSBL(params.Host, &net.Resolver{
		PreferGo: true,
	})

	ob := make(closer)

	go func() {
		ticker := time.NewTicker(params.Timeout / 3)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				decayMap.Decay()
			case <-ob:
				return
			}
		}
	}()

	// allow freeing the ticker/decay map
	reg.Object = ob

	reg.IssueChallenge = func(w http.ResponseWriter, r *http.Request, key challenge.Key, expiry time.Time) challenge.VerifyResult {

		data := challenge.RequestDataFromContext(r.Context())

		result, err := lookup(r.Context(), params.Decay, params.Timeout, dnsbl, decayMap, data.RemoteAddress)
		if err != nil {
			data.State.Logger(r).Debug("dnsbl lookup failed", "address", data.RemoteAddress.String(), "result", result, "err", err)
		}

		if err != nil {
			return challenge.VerifyResultFail
		}

		if result.Bad() {
			token, err := reg.IssueChallengeToken(state.PrivateKey(), key, nil, expiry, false)
			if err != nil {
				return challenge.VerifyResultFail
			}
			utils.SetCookie(utils.CookiePrefix+reg.Name, token, expiry, w, r)
			return challenge.VerifyResultNotOK
		} else {
			token, err := reg.IssueChallengeToken(state.PrivateKey(), key, nil, expiry, true)
			if err != nil {
				return challenge.VerifyResultFail
			}
			utils.SetCookie(utils.CookiePrefix+reg.Name, token, expiry, w, r)
			return challenge.VerifyResultOK
		}
	}

	return nil
}
