package challenge

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"git.gammaspectra.live/git/go-away/utils"
	"github.com/google/cel-go/common/types"
	"net"
	"net/http"
	"strings"
	"time"
)

type requestDataContextKey struct {
}

func RequestDataFromContext(ctx context.Context) *RequestData {
	return ctx.Value(requestDataContextKey{}).(*RequestData)
}

func CreateRequestData(r *http.Request, state StateInterface) (*http.Request, *RequestData) {

	var data RequestData
	// generate random id, todo: is this fast?
	_, _ = rand.Read(data.Id[:])
	data.RemoteAddress = utils.GetRequestAddress(r, state.Settings().ClientIpHeader)
	data.ChallengeVerify = make(map[Id]VerifyResult, len(state.GetChallenges()))
	data.ChallengeState = make(map[Id]VerifyState, len(state.GetChallenges()))
	data.Time = time.Now().UTC()
	data.State = state

	var ja3n, ja4 string
	if fp := utils.GetTLSFingerprint(r); fp != nil {
		if ja3nPtr := fp.JA3N(); ja3nPtr != nil {
			ja3n = ja3nPtr.String()
			r.Header.Set("X-TLS-Fingerprint-JA3N", ja3n)
		}
		if ja4Ptr := fp.JA4(); ja4Ptr != nil {
			ja4 = ja4Ptr.String()
			r.Header.Set("X-TLS-Fingerprint-JA4", ja4)
		}
	}

	data.ProgramEnv = map[string]any{
		"host":          r.Host,
		"method":        r.Method,
		"remoteAddress": data.RemoteAddress,
		"userAgent":     r.UserAgent(),
		"path":          r.URL.Path,
		"fpJA3N":        ja3n,
		"fpJA4":         ja4,
		"query": func() map[string]string {
			result := make(map[string]string)
			for k, v := range r.URL.Query() {
				result[k] = strings.Join(v, ",")
			}
			return result
		}(),
		"headers": func() map[string]string {
			result := make(map[string]string)
			for k, v := range r.Header {
				result[k] = strings.Join(v, ",")
			}
			return result
		}(),
	}

	r = r.WithContext(context.WithValue(r.Context(), requestDataContextKey{}, &data))

	return r, &data
}

type RequestId [16]byte

func (id RequestId) String() string {
	return hex.EncodeToString(id[:])
}

type RequestData struct {
	Id              RequestId
	ProgramEnv      map[string]any
	Time            time.Time
	ChallengeVerify map[Id]VerifyResult
	ChallengeState  map[Id]VerifyState
	RemoteAddress   net.IP
	State           StateInterface
}

func (d *RequestData) EvaluateChallenges(w http.ResponseWriter, r *http.Request) {
	for _, reg := range d.State.GetChallenges() {
		key := GetChallengeKeyForRequest(d.State, reg, d.Expiration(reg.Duration), r)
		verifyResult, verifyState, err := reg.VerifyChallengeToken(d.State.PublicKey(), key, r)
		if err != nil && !errors.Is(err, http.ErrNoCookie) {
			// clear invalid cookie
			utils.ClearCookie(utils.CookiePrefix+reg.Name, w, r)
		}

		// prevent evaluating the challenge if not solved
		if !verifyResult.Ok() && reg.Condition != nil {
			out, _, err := reg.Condition.Eval(d.ProgramEnv)
			// verify eligibility
			if err != nil {
				d.State.Logger(r).Error(err.Error(), "challenge", reg.Name)
			} else if out != nil && out.Type() == types.BoolType {
				if out.Equal(types.True) != types.True {
					// skip challenge match due to precondition!
					verifyResult = VerifyResultSkip
					continue
				}
			}
		}
		d.ChallengeVerify[reg.Id()] = verifyResult
		d.ChallengeState[reg.Id()] = verifyState
	}

	if d.State.Settings().BackendIpHeader != "" {
		if d.State.Settings().ClientIpHeader != "" {
			r.Header.Del(d.State.Settings().ClientIpHeader)
		}
		r.Header.Set(d.State.Settings().BackendIpHeader, d.RemoteAddress.String())
	}

	// send these to client so we consistently get the headers
	//w.Header().Set("Accept-CH", "Sec-CH-UA, Sec-CH-UA-Platform")
	//w.Header().Set("Critical-CH", "Sec-CH-UA, Sec-CH-UA-Platform")
}

func (d *RequestData) Expiration(duration time.Duration) time.Time {
	return d.Time.Add(duration).Round(duration)
}

func (d *RequestData) HasValidChallenge(id Id) bool {
	return d.ChallengeVerify[id].Ok()
}

func (d *RequestData) Headers(headers http.Header) {
	headers.Set("X-Away-Id", d.Id.String())

	for id, result := range d.ChallengeVerify {
		if result.Ok() {
			c, ok := d.State.GetChallenge(id)
			if !ok {
				panic("challenge not found")
			}

			headers.Set(fmt.Sprintf("X-Away-Challenge-%s-Result", c.Name), result.String())
			headers.Set(fmt.Sprintf("X-Away-Challenge-%s-State", c.Name), d.ChallengeState[id].String())
		}
	}
}
