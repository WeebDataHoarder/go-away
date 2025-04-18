package challenge

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"git.gammaspectra.live/git/go-away/lib/condition"
	"git.gammaspectra.live/git/go-away/lib/policy"
	"git.gammaspectra.live/git/go-away/utils"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/goccy/go-yaml/ast"
	"github.com/google/cel-go/cel"
	"io"
	"math/rand/v2"
	"net/http"
	"path"
	"strings"
	"time"
)

type Register map[Id]*Registration

func (r Register) Get(id Id) (*Registration, bool) {
	c, ok := r[id]
	return c, ok
}

func (r Register) GetByName(name string) (*Registration, Id, bool) {
	for id, c := range r {
		if c.Name == name {
			return c, id, true
		}
	}

	return nil, 0, false
}

var idCounter Id

// DefaultDuration TODO: adjust
const DefaultDuration = time.Hour * 24 * 7

func (r Register) Create(state StateInterface, name string, pol policy.Challenge, replacer *strings.Replacer) (*Registration, Id, error) {
	runtime, ok := Runtimes[pol.Runtime]
	if !ok {
		return nil, 0, fmt.Errorf("unknown challenge runtime %s", pol.Runtime)
	}

	reg := &Registration{
		Name:     name,
		Path:     path.Join(state.UrlPath(), "challenge", name),
		Duration: pol.Duration,
	}

	if reg.Duration == 0 {
		reg.Duration = DefaultDuration
	}

	// allow nesting
	var conditions []string
	for _, cond := range pol.Conditions {
		if replacer != nil {
			cond = replacer.Replace(cond)
		}
		conditions = append(conditions, cond)
	}

	if len(conditions) > 0 {
		ast, err := condition.FromStrings(state.ProgramEnv(), condition.OperatorOr, conditions...)
		if err != nil {
			return nil, 0, fmt.Errorf("error compiling conditions: %v", err)
		}
		reg.Condition, err = condition.Program(state.ProgramEnv(), ast)
		if err != nil {
			return nil, 0, fmt.Errorf("error compiling program: %v", err)
		}
	}

	if _, oldId, ok := r.GetByName(reg.Name); ok {
		reg.id = oldId
	} else {
		idCounter++
		reg.id = idCounter
	}

	err := runtime(state, reg, pol.Parameters)
	if err != nil {
		return nil, 0, fmt.Errorf("error filling registration: %v", err)
	}
	r[reg.id] = reg
	return reg, reg.id, nil
}

func (r Register) Add(c *Registration) Id {
	if _, oldId, ok := r.GetByName(c.Name); ok {
		c.id = oldId
		r[oldId] = c
		return oldId
	} else {
		idCounter++
		c.id = idCounter
		r[idCounter] = c
		return idCounter
	}
}

type Registration struct {
	// id The assigned internal identifier
	id Id

	// Name The unique name for this challenge
	Name string

	// Class whether this challenge is transparent or otherwise
	Class Class

	// Condition A CEL condition which is passed the same environment as general rules.
	// If nil, always true
	// If non-nil, must return true for this challenge to be allowed to be executed
	Condition cel.Program

	// Path The url path that this challenge is hosted under for the Handler to be called.
	Path string

	// Duration How long this challenge will be valid when passed
	Duration time.Duration

	// Handler An HTTP handler for all requests coming on the Path
	// This handler will need to handle MakeChallengeUrlSuffix and VerifyChallengeUrlSuffix as well if needed
	// Recommended to use http.ServeMux
	Handler http.Handler

	// Verify Verify an issued token
	Verify            VerifyFunc
	VerifyProbability float64

	// IssueChallenge Issues a challenge to a request.
	// If Class is ClassTransparent and VerifyResult is !VerifyResult.Ok(), continue with other challenges
	// TODO: have this return error as well
	IssueChallenge func(w http.ResponseWriter, r *http.Request, key Key, expiry time.Time) VerifyResult

	// Object used to handle state or similar
	// Can be nil if no state is needed
	// If non-nil must implement io.Closer even if there's nothing to do
	Object io.Closer
}

type VerifyFunc func(key Key, token []byte, r *http.Request) (VerifyResult, error)

type Token struct {
	Name   string `json:"name"`
	Key    []byte `json:"key"`
	Result []byte `json:"result,omitempty"`
	Ok     bool   `json:"ok"`

	Expiry    jwt.NumericDate `json:"exp,omitempty"`
	NotBefore jwt.NumericDate `json:"nbf,omitempty"`
	IssuedAt  jwt.NumericDate `json:"iat,omitempty"`
}

func (reg Registration) Id() Id {
	return reg.id
}

func (reg Registration) IssueChallengeToken(privateKey ed25519.PrivateKey, key Key, result []byte, until time.Time, ok bool) (token string, err error) {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.EdDSA,
		Key:       privateKey,
	}, nil)
	if err != nil {
		return "", err
	}

	token, err = jwt.Signed(signer).Claims(Token{
		Name:      reg.Name,
		Key:       key[:],
		Result:    result,
		Ok:        ok,
		Expiry:    jwt.NumericDate(until.Unix()),
		NotBefore: jwt.NumericDate(time.Now().UTC().AddDate(0, 0, -1).Unix()),
		IssuedAt:  jwt.NumericDate(time.Now().UTC().Unix()),
	}).Serialize()
	if err != nil {
		return "", err
	}
	return token, nil
}

var ErrVerifyKeyMismatch = errors.New("verify: key mismatch")
var ErrVerifyVerifyMismatch = errors.New("verify: verification mismatch")
var ErrTokenExpired = errors.New("token: expired")

func (reg Registration) VerifyChallengeToken(publicKey ed25519.PublicKey, expectedKey Key, r *http.Request) (VerifyResult, VerifyState, error) {
	cookie, err := r.Cookie(utils.CookiePrefix + reg.Name)
	if err != nil {
		return VerifyResultNone, VerifyStateNone, err
	}
	if cookie == nil {
		return VerifyResultNone, VerifyStateNone, http.ErrNoCookie
	}

	token, err := jwt.ParseSigned(cookie.Value, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return VerifyResultFail, VerifyStateNone, err
	}

	var i Token
	err = token.Claims(publicKey, &i)
	if err != nil {
		return VerifyResultFail, VerifyStateNone, err
	}

	if i.Name != reg.Name {
		return VerifyResultFail, VerifyStateNone, errors.New("token invalid name")
	}
	if i.Expiry.Time().Compare(time.Now()) < 0 {
		return VerifyResultFail, VerifyStateNone, ErrTokenExpired
	}
	if i.NotBefore.Time().Compare(time.Now()) > 0 {
		return VerifyResultFail, VerifyStateNone, errors.New("token not valid yet")
	}

	if bytes.Compare(expectedKey[:], i.Key) != 0 {
		return VerifyResultFail, VerifyStateNone, ErrVerifyKeyMismatch
	}

	if reg.Verify != nil {
		if rand.Float64() < reg.VerifyProbability {
			// random spot check
			if ok, err := reg.Verify(expectedKey, i.Result, r); err != nil {
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

	if !i.Ok {
		return VerifyResultNotOK, VerifyStateBrief, nil
	}
	return VerifyResultOK, VerifyStateBrief, nil
}

type FillRegistration func(state StateInterface, reg *Registration, parameters ast.Node) error

var Runtimes = make(map[string]FillRegistration)
