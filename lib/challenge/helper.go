package challenge

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"git.gammaspectra.live/git/go-away/utils"
	"net/http"
	"net/url"
)

func NewKeyVerifier() (verify VerifyFunc, issue func(key Key) string) {
	return func(key Key, token []byte, r *http.Request) (VerifyResult, error) {
			expectedKey, err := hex.DecodeString(string(token))
			if err != nil {
				return VerifyResultFail, err
			}
			if subtle.ConstantTimeCompare(key[:], expectedKey) == 1 {
				return VerifyResultOK, nil
			}
			return VerifyResultFail, errors.New("invalid token")
		}, func(key Key) string {
			return hex.EncodeToString(key[:])
		}
}

const (
	QueryArgPrefix    = "__goaway"
	QueryArgReferer   = QueryArgPrefix + "_referer"
	QueryArgRedirect  = QueryArgPrefix + "_redirect"
	QueryArgRequestId = QueryArgPrefix + "_id"
	QueryArgChallenge = QueryArgPrefix + "_challenge"
	QueryArgToken     = QueryArgPrefix + "_token"
)

const MakeChallengeUrlSuffix = "/make-challenge"
const VerifyChallengeUrlSuffix = "/verify-challenge"

func GetVerifyInformation(r *http.Request, reg *Registration) (requestId RequestId, redirect, token string, err error) {

	if r.FormValue(QueryArgChallenge) != reg.Name {
		return RequestId{}, "", "", fmt.Errorf("unexpected challenge: got %s", r.FormValue(QueryArgChallenge))
	}

	requestIdHex := r.FormValue(QueryArgRequestId)

	if len(requestId) != hex.DecodedLen(len(requestIdHex)) {
		return RequestId{}, "", "", errors.New("invalid request id")
	}
	n, err := hex.Decode(requestId[:], []byte(requestIdHex))
	if err != nil {
		return RequestId{}, "", "", err
	} else if n != len(requestId) {
		return RequestId{}, "", "", errors.New("invalid request id")
	}

	token = r.FormValue(QueryArgToken)
	redirect, err = utils.EnsureNoOpenRedirect(r.FormValue(QueryArgRedirect))
	if err != nil {
		return RequestId{}, "", "", err
	}
	return
}

func VerifyUrl(r *http.Request, reg *Registration, token string) (*url.URL, error) {

	redirectUrl, err := RedirectUrl(r, reg)
	if err != nil {
		return nil, err
	}

	uri := new(url.URL)
	uri.Path = reg.Path + VerifyChallengeUrlSuffix

	data := RequestDataFromContext(r.Context())
	values := uri.Query()
	values.Set(QueryArgRequestId, data.Id.String())
	values.Set(QueryArgRedirect, redirectUrl.String())
	values.Set(QueryArgToken, token)
	values.Set(QueryArgChallenge, reg.Name)
	uri.RawQuery = values.Encode()

	return uri, nil
}

func RedirectUrl(r *http.Request, reg *Registration) (*url.URL, error) {
	uri, err := url.ParseRequestURI(r.URL.String())
	if err != nil {
		return nil, err
	}

	data := RequestDataFromContext(r.Context())
	values := uri.Query()
	values.Set(QueryArgRequestId, data.Id.String())
	values.Set(QueryArgReferer, r.Referer())
	values.Set(QueryArgChallenge, reg.Name)
	uri.RawQuery = values.Encode()

	return uri, nil
}

func VerifyHandlerChallengeResponseFunc(state StateInterface, data *RequestData, w http.ResponseWriter, r *http.Request, verifyResult VerifyResult, err error, redirect string) {
	if err != nil {
		state.ErrorPage(w, r, http.StatusBadRequest, err, redirect)
		return
	} else if !verifyResult.Ok() {
		state.ErrorPage(w, r, http.StatusForbidden, fmt.Errorf("access denied: failed challenge"), redirect)
		return
	}
	http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
}

func VerifyHandlerFunc(state StateInterface, reg *Registration, verify VerifyFunc, responseFunc func(state StateInterface, data *RequestData, w http.ResponseWriter, r *http.Request, verifyResult VerifyResult, err error, redirect string)) http.HandlerFunc {
	if verify == nil {
		verify = reg.Verify
	}
	if responseFunc == nil {
		responseFunc = VerifyHandlerChallengeResponseFunc
	}
	return func(w http.ResponseWriter, r *http.Request) {
		data := RequestDataFromContext(r.Context())
		requestId, redirect, token, err := GetVerifyInformation(r, reg)
		if err != nil {
			state.ChallengeFailed(r, reg, err, "", nil)
			responseFunc(state, data, w, r, VerifyResultFail, fmt.Errorf("internal error: %w", err), "")
			return
		}
		data.Id = requestId

		err = func() (err error) {
			expiration := data.Expiration(reg.Duration)
			key := GetChallengeKeyForRequest(state, reg, expiration, r)

			verifyResult, err := verify(key, []byte(token), r)
			if err != nil {
				return err
			} else if !verifyResult.Ok() {
				utils.ClearCookie(utils.CookiePrefix+reg.Name, w, r)
				state.ChallengeFailed(r, reg, nil, redirect, nil)
				responseFunc(state, data, w, r, verifyResult, nil, redirect)
				return nil
			}

			challengeToken, err := reg.IssueChallengeToken(state.PrivateKey(), key, []byte(token), expiration, true)
			if err != nil {
				utils.ClearCookie(utils.CookiePrefix+reg.Name, w, r)
			} else {
				utils.SetCookie(utils.CookiePrefix+reg.Name, challengeToken, expiration, w, r)
			}
			data.ChallengeVerify[reg.id] = verifyResult
			state.ChallengePassed(r, reg, redirect, nil)

			responseFunc(state, data, w, r, verifyResult, nil, redirect)
			return nil
		}()
		if err != nil {
			utils.ClearCookie(utils.CookiePrefix+reg.Name, w, r)
			state.ChallengeFailed(r, reg, err, redirect, nil)
			responseFunc(state, data, w, r, VerifyResultFail, fmt.Errorf("access denied: error in challenge %s: %w", reg.Name, err), redirect)
			return
		}
	}
}
