package policy

import (
	"net/http"
)

type Settings struct {
	Backends               map[string]http.Handler
	PrivateKeySeed         []byte
	Debug                  bool
	PackageName            string
	ChallengeTemplate      string
	ChallengeTemplateTheme string
	ClientIpHeader         string
	BackendIpHeader        string

	ChallengeResponseCode int
}
