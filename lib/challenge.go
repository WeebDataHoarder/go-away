package lib

import (
	_ "git.gammaspectra.live/git/go-away/lib/challenge/cookie"
	_ "git.gammaspectra.live/git/go-away/lib/challenge/dnsbl"
	_ "git.gammaspectra.live/git/go-away/lib/challenge/http"
	_ "git.gammaspectra.live/git/go-away/lib/challenge/preload-link"
	_ "git.gammaspectra.live/git/go-away/lib/challenge/refresh"
	_ "git.gammaspectra.live/git/go-away/lib/challenge/resource-load"
	_ "git.gammaspectra.live/git/go-away/lib/challenge/wasm"
)

// This file loads embedded challenge runtimes so their init() is called
