package utils

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"
	"strings"
	"sync/atomic"
)

type tlsFingerprintKey struct{}
type TLSFingerprint struct {
	ja3n atomic.Pointer[TLSFingerprintJA3N]
	ja4  atomic.Pointer[TLSFingerprintJA4]
}

type TLSFingerprintJA3N [md5.Size]byte

func (f TLSFingerprintJA3N) String() string {
	return hex.EncodeToString(f[:])
}

type TLSFingerprintJA4 struct {
	A [10]byte
	B [6]byte
	C [6]byte
}

func (f TLSFingerprintJA4) String() string {
	return strings.Join([]string{
		string(f.A[:]),
		hex.EncodeToString(f.B[:]),
		hex.EncodeToString(f.C[:]),
	}, "_")
}

func (f *TLSFingerprint) JA3N() *TLSFingerprintJA3N {
	return f.ja3n.Load()
}

func (f *TLSFingerprint) JA4() *TLSFingerprintJA4 {
	return f.ja4.Load()
}

const greaseMask = 0x0F0F
const greaseValue = 0x0a0a

// TLS extension numbers
const (
	extensionServerName              uint16 = 0
	extensionStatusRequest           uint16 = 5
	extensionSupportedCurves         uint16 = 10 // supported_groups in TLS 1.3, see RFC 8446, Section 4.2.7
	extensionSupportedPoints         uint16 = 11
	extensionSignatureAlgorithms     uint16 = 13
	extensionALPN                    uint16 = 16
	extensionSCT                     uint16 = 18
	extensionExtendedMasterSecret    uint16 = 23
	extensionSessionTicket           uint16 = 35
	extensionPreSharedKey            uint16 = 41
	extensionEarlyData               uint16 = 42
	extensionSupportedVersions       uint16 = 43
	extensionCookie                  uint16 = 44
	extensionPSKModes                uint16 = 45
	extensionCertificateAuthorities  uint16 = 47
	extensionSignatureAlgorithmsCert uint16 = 50
	extensionKeyShare                uint16 = 51
	extensionQUICTransportParameters uint16 = 57
	extensionRenegotiationInfo       uint16 = 0xff01
	extensionECHOuterExtensions      uint16 = 0xfd00
	extensionEncryptedClientHello    uint16 = 0xfe0d
)

func GetTLSFingerprint(r *http.Request) *TLSFingerprint {
	ptr := r.Context().Value(tlsFingerprintKey{})
	if fpPtr, ok := ptr.(*TLSFingerprint); ok && ptr != nil && fpPtr != nil {
		return fpPtr
	}
	return nil
}
