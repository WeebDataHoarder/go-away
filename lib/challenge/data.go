package challenge

import (
	"bytes"
	http_cel "codeberg.org/gone/http-cel"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"git.gammaspectra.live/git/go-away/utils"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/traits"
	"maps"
	unsaferand "math/rand/v2"
	"net/http"
	"net/netip"
	"net/textproto"
	"strings"
	"time"
)

type requestDataContextKey struct {
}

func RequestDataFromContext(ctx context.Context) *RequestData {
	val := ctx.Value(requestDataContextKey{})
	if val == nil {
		return nil
	}
	return val.(*RequestData)
}

type RequestId [16]byte

func (id RequestId) String() string {
	return hex.EncodeToString(id[:])
}

type RequestData struct {
	Id                   RequestId
	Time                 time.Time
	ChallengeVerify      map[Id]VerifyResult
	ChallengeState       map[Id]VerifyState
	ChallengeMap         TokenChallengeMap
	challengeMapModified bool

	RemoteAddress   netip.AddrPort
	State           StateInterface
	cookieName      string
	issuedChallenge string

	ExtraHeaders http.Header

	r *http.Request

	fp     map[string]string
	header traits.Mapper
	query  traits.Mapper

	opts map[string]string
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

	data.ExtraHeaders = make(http.Header)

	data.fp = make(map[string]string, 2)

	if fp := utils.GetTLSFingerprint(r); fp != nil {
		if ja3nPtr := fp.JA3N(); ja3nPtr != nil {
			ja3n := ja3nPtr.String()
			data.fp["ja3n"] = ja3n
		}
		if ja4Ptr := fp.JA4(); ja4Ptr != nil {
			ja4 := ja4Ptr.String()
			data.fp["ja4"] = ja4
		}
	}

	q := r.URL.Query()

	if q.Has(QueryArgChallenge) {
		data.issuedChallenge = q.Get(QueryArgChallenge)
	}

	// delete query parameters that were set by go-away
	for k := range q {
		if strings.HasPrefix(k, QueryArgPrefix) {
			q.Del(k)
		}
	}

	data.query = http_cel.NewValuesMap(q)
	data.header = http_cel.NewMIMEMap(textproto.MIMEHeader(r.Header))
	data.opts = make(map[string]string)

	r = r.WithContext(context.WithValue(r.Context(), requestDataContextKey{}, &data))
	r = utils.SetRemoteAddress(r, data.RemoteAddress)
	data.r = r

	data.cookieName = utils.DefaultCookiePrefix + hex.EncodeToString(data.cookieHostKey()) + "-state"

	return r, &data
}

func (d *RequestData) ResolveName(name string) (any, bool) {
	switch name {
	case "host":
		return d.r.Host, true
	case "method":
		return d.r.Method, true
	case "remoteAddress":
		return d.RemoteAddress.Addr().AsSlice(), true
	case "userAgent":
		return d.r.UserAgent(), true
	case "path":
		return d.r.URL.Path, true
	case "query":
		return d.query, true
	case "headers":
		return d.header, true
	case "fp":
		return d.fp, true
	default:
		return nil, false
	}
}

func (d *RequestData) Parent() cel.Activation {
	return nil
}

func (d *RequestData) NetworkPrefix() netip.Addr {
	address := d.RemoteAddress.Addr().Unmap()
	if address.Is4() {
		// Take a /24 for IPv4
		prefix, _ := address.Prefix(24)
		return prefix.Addr()
	} else {
		// Take a /64 for IPv6
		prefix, _ := address.Prefix(64)
		return prefix.Addr()
	}
}

const (
	RequestOptBackendHost       = "backend-host"
	RequestOptProxyMetaTags     = "proxy-meta-tags"
	RequestOptProxySafeLinkTags = "proxy-safe-link-tags"
)

func (d *RequestData) SetOpt(n, v string) {
	d.opts[n] = v
}

func (d *RequestData) GetOpt(n, def string) string {
	v, ok := d.opts[n]
	if !ok {
		return def
	}
	return v
}

func (d *RequestData) GetOptBool(n string, def bool) bool {
	v, ok := d.opts[n]
	if !ok {
		return def
	}
	switch v {
	case "true", "t", "1", "yes", "yep", "y", "ok":
		return true
	case "false", "f", "0", "no", "nope", "n", "err":
		return false
	default:
		return def
	}
}

func (d *RequestData) BackendHost() (http.Handler, string) {
	host := d.r.Host

	if opt := d.GetOpt(RequestOptBackendHost, ""); opt != "" && opt != host {
		host = d.r.Host
	}

	return d.State.GetBackend(host), host
}

func (d *RequestData) ClearChallengeToken(reg *Registration) {
	delete(d.ChallengeMap, reg.Name)
	d.challengeMapModified = true
}

func (d *RequestData) IssueChallengeToken(reg *Registration, key Key, result []byte, until time.Time, ok bool) {
	d.ChallengeMap[reg.Name] = TokenChallenge{
		Key:      key[:],
		Result:   result,
		Ok:       ok,
		Expiry:   jwt.NumericDate(until.Unix()),
		IssuedAt: jwt.NumericDate(time.Now().UTC().Unix()),
	}
	d.challengeMapModified = true
}

var ErrVerifyKeyMismatch = errors.New("verify: key mismatch")
var ErrVerifyVerifyMismatch = errors.New("verify: verification mismatch")
var ErrTokenExpired = errors.New("token: expired")

func (d *RequestData) VerifyChallengeToken(reg *Registration, token TokenChallenge, expectedKey Key) (VerifyResult, VerifyState, error) {
	if token.Expiry.Time().Compare(time.Now()) < 0 {
		return VerifyResultFail, VerifyStateNone, ErrTokenExpired
	}
	if token.NotBefore.Time().Compare(time.Now()) > 0 {
		return VerifyResultFail, VerifyStateNone, errors.New("token not valid yet")
	}

	if bytes.Compare(expectedKey[:], token.Key) != 0 {
		return VerifyResultFail, VerifyStateNone, ErrVerifyKeyMismatch
	}

	if reg.Verify != nil {
		if unsaferand.Float64() < reg.VerifyProbability {
			// random spot check
			if ok, err := reg.Verify(expectedKey, token.Result, d.r); err != nil {
				return VerifyResultFail, VerifyStateFull, err
			} else if ok == VerifyResultNotOK {
				return VerifyResultNotOK, VerifyStateFull, nil
			} else if !ok.Ok() {
				return ok, VerifyStateFull, ErrVerifyVerifyMismatch
			} else {
				return ok, VerifyStateFull, nil
			}
		}
	}

	if !token.Ok {
		return VerifyResultNotOK, VerifyStateBrief, nil
	}
	return VerifyResultOK, VerifyStateBrief, nil
}

func (d *RequestData) verifyChallenge(reg *Registration, key Key) (verifyResult VerifyResult, verifyState VerifyState, err error) {

	token, ok := d.ChallengeMap[reg.Name]
	if !ok {
		verifyResult = VerifyResultFail
		verifyState = VerifyStateNone
	} else {
		verifyResult, verifyState, err = d.VerifyChallengeToken(reg, token, key)
		if err != nil && !errors.Is(err, http.ErrNoCookie) {
			// clear invalid state
			d.ClearChallengeToken(reg)
		}

		// prevent evaluating the challenge if not solved
		if !verifyResult.Ok() && reg.Condition != nil {
			out, _, err := reg.Condition.Eval(d)
			// verify eligibility
			if err != nil {
				d.State.Logger(d.r).Error(err.Error(), "challenge", reg.Name)
			} else if out != nil && out.Type() == types.BoolType {
				if out.Equal(types.True) != types.True {
					// skip challenge match due to precondition!
					verifyResult = VerifyResultSkip
					return verifyResult, verifyState, err
				}
			}
		}
	}

	if !verifyResult.Ok() && d.issuedChallenge == reg.Name {
		// we issued the challenge, must skip to prevent loops
		verifyResult = VerifyResultSkip
	}

	return verifyResult, verifyState, err
}

func (d *RequestData) EvaluateChallenges(w http.ResponseWriter, r *http.Request) {

	challengeMap, err := d.verifyChallengeState()
	if err != nil {
		if !errors.Is(err, http.ErrNoCookie) {
			//clear invalid cookie and continue
			utils.ClearCookie(d.cookieName, w, r)
		}
		challengeMap = make(TokenChallengeMap)
	}
	d.ChallengeMap = challengeMap

	for _, reg := range d.State.GetChallenges() {

		key := GetChallengeKeyForRequest(d.State, reg, d.Expiration(reg.Duration), r)
		verifyResult, verifyState, err := d.verifyChallenge(reg, key)
		if err != nil {
			// clear invalid state
			d.ClearChallengeToken(reg)
		}

		d.ChallengeVerify[reg.Id()] = verifyResult
		d.ChallengeState[reg.Id()] = verifyState
	}
}

func (d *RequestData) Expiration(duration time.Duration) time.Time {
	return d.Time.Add(duration).Round(duration)
}

func (d *RequestData) HasValidChallenge(id Id) bool {
	return d.ChallengeVerify[id].Ok()
}

func (d *RequestData) ResponseHeaders(w http.ResponseWriter) {
	// send these to client so we consistently get the headers
	//w.Header().Set("Accept-CH", "Sec-CH-UA, Sec-CH-UA-Platform")
	//w.Header().Set("Critical-CH", "Sec-CH-UA, Sec-CH-UA-Platform")

	if d.State.Settings().MainName != "" {
		w.Header().Add("Via", fmt.Sprintf("%s %s@%s", d.r.Proto, d.State.Settings().MainName, d.State.Settings().MainVersion))
	}

	if d.challengeMapModified {
		expiration := d.Expiration(DefaultDuration)
		if token, err := d.issueChallengeState(expiration); err == nil {
			utils.SetCookie(d.cookieName, token, expiration, w, d.r)
		} else {
			d.State.Logger(d.r).Error("error while issuing cookie", "error", err)
		}
	}
}

func (d *RequestData) RequestHeaders(headers http.Header) {
	headers.Set("X-Away-Id", d.Id.String())

	if d.State.Settings().BackendIpHeader != "" {
		if d.State.Settings().ClientIpHeader != "" {
			headers.Del(d.State.Settings().ClientIpHeader)
		}
		headers.Set(d.State.Settings().BackendIpHeader, d.RemoteAddress.Addr().Unmap().String())
	}

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

	if ja4, ok := d.fp["fp4"]; ok {
		headers.Set("X-TLS-Fingerprint-JA4", ja4)
	}

	if ja3n, ok := d.fp["ja3n"]; ok {
		headers.Set("X-TLS-Fingerprint-JA3N", ja3n)
	}

	maps.Copy(headers, d.ExtraHeaders)
}

type Token struct {
	State TokenChallengeMap `json:"state"`

	Expiry    jwt.NumericDate `json:"exp,omitempty"`
	NotBefore jwt.NumericDate `json:"nbf,omitempty"`
	IssuedAt  jwt.NumericDate `json:"iat,omitempty"`
}

type TokenChallengeMap map[string]TokenChallenge

type TokenChallenge struct {
	Key    []byte `json:"key"`
	Result []byte `json:"result,omitempty"`
	Ok     bool   `json:"ok"`

	Expiry    jwt.NumericDate `json:"exp,omitempty"`
	NotBefore jwt.NumericDate `json:"nbf,omitempty"`
	IssuedAt  jwt.NumericDate `json:"iat,omitempty"`
}

func (d *RequestData) verifyChallengeStateCookie(cookie *http.Cookie) (TokenChallengeMap, error) {
	cookie, err := d.r.Cookie(d.cookieName)
	if err != nil {
		return nil, err
	}
	if cookie == nil {
		return nil, http.ErrNoCookie
	}
	encryptedToken, err := jwt.ParseSignedAndEncrypted(cookie.Value,
		[]jose.KeyAlgorithm{jose.DIRECT},
		[]jose.ContentEncryption{jose.A256GCM},
		[]jose.SignatureAlgorithm{jose.EdDSA},
	)
	if err != nil {
		return nil, err
	}
	signedToken, err := encryptedToken.Decrypt(d.cookieKey())
	if err != nil {
		return nil, err
	}
	var i Token
	err = signedToken.Claims(d.State.PublicKey(), &i)
	if err != nil {
		return nil, err
	}

	if i.Expiry.Time().Compare(time.Now()) < 0 {
		return nil, ErrTokenExpired
	}
	if i.NotBefore.Time().Compare(time.Now()) > 0 {
		return nil, errors.New("token not valid yet")
	}

	return i.State, nil
}

func (d *RequestData) verifyChallengeState() (state TokenChallengeMap, err error) {
	var cookies []*http.Cookie
	for _, cookie := range d.r.Cookies() {
		if cookie.Name == d.cookieName {
			cookies = append(cookies, cookie)
		}
	}

	if len(cookies) == 0 {
		return nil, http.ErrNoCookie
	}
	for _, cookie := range cookies {
		state, err = d.verifyChallengeStateCookie(cookie)
		if err == nil {
			return state, nil
		}
	}
	return state, err
}

func (d *RequestData) issueChallengeState(until time.Time) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.EdDSA,
		Key:       d.State.PrivateKey(),
	}, nil)
	if err != nil {
		return "", err
	}

	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{
		Algorithm: jose.DIRECT,
		Key:       d.cookieKey(),
	}, (&jose.EncrypterOptions{
		Compression: jose.DEFLATE,
	}).WithContentType("JWT"))
	if err != nil {
		return "", err
	}

	return jwt.SignedAndEncrypted(signer, encrypter).Claims(Token{
		State:     d.ChallengeMap,
		Expiry:    jwt.NumericDate(until.Unix()),
		NotBefore: jwt.NumericDate(time.Now().UTC().AddDate(0, 0, -1).Unix()),
		IssuedAt:  jwt.NumericDate(time.Now().UTC().Unix()),
	}).Serialize()
}

func (d *RequestData) cookieKey() []byte {
	sum := sha256.New()
	sum.Write([]byte(d.r.Host))
	sum.Write([]byte{0})
	sum.Write(d.NetworkPrefix().AsSlice())
	sum.Write([]byte{0})
	sum.Write(d.State.PrivateKey())
	sum.Write([]byte{0})
	// version/compressor
	sum.Write([]byte("1.0/DEFLATE"))
	sum.Write([]byte{0})

	return sum.Sum(nil)
}

func (d *RequestData) cookieHostKey() []byte {
	sum := sha256.New()
	sum.Write([]byte(d.r.Host))
	sum.Write([]byte{0})
	sum.Write(d.NetworkPrefix().AsSlice())
	sum.Write([]byte{0})

	return sum.Sum(nil)[:6]
}
