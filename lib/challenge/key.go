package challenge

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"time"
)

type Key [KeySize]byte

const KeySize = sha256.Size

func (k *Key) Set(flags KeyFlags) {
	(*k)[0] |= uint8(flags)
}
func (k *Key) Get(flags KeyFlags) KeyFlags {
	return KeyFlags((*k)[0] & uint8(flags))
}
func (k *Key) Unset(flags KeyFlags) {
	(*k)[0] = (*k)[0] & ^(uint8(flags))
}

type KeyFlags uint8

const (
	KeyFlagIsIPv4 = KeyFlags(1 << iota)
)

func KeyFromString(s string) (Key, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return Key{}, err
	}
	if len(b) != KeySize {
		return Key{}, errors.New("invalid challenge key")
	}
	return Key(b), nil
}

func GetChallengeKeyForRequest(state StateInterface, reg *Registration, until time.Time, r *http.Request) Key {
	data := RequestDataFromContext(r.Context())
	address := data.RemoteAddress
	hasher := sha256.New()
	hasher.Write([]byte("challenge\x00"))
	hasher.Write([]byte(reg.Name))
	hasher.Write([]byte{0})
	hasher.Write(address.To16())
	hasher.Write([]byte{0})

	// specific headers
	for _, k := range []string{
		"Accept-Language",
		// General browser information
		"User-Agent",
		// TODO: not sent in preload
		//"Sec-Ch-Ua",
		//"Sec-Ch-Ua-Platform",
	} {
		hasher.Write([]byte(r.Header.Get(k)))
		hasher.Write([]byte{0})
	}
	hasher.Write([]byte{0})
	_ = binary.Write(hasher, binary.LittleEndian, until.UTC().Unix())
	hasher.Write([]byte{0})
	hasher.Write(state.PublicKey())
	hasher.Write([]byte{0})

	sum := Key(hasher.Sum(nil))

	sum[0] = 0

	if address.To4() != nil {
		// Is IPv4, mark
		sum.Set(KeyFlagIsIPv4)
	}
	return Key(sum)
}
