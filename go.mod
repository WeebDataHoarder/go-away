module git.gammaspectra.live/git/go-away

go 1.22.12

require (
	codeberg.org/gone/http-cel v1.0.0
	codeberg.org/meta/gzipped/v2 v2.0.0-20231111234332-aa70c3194756
	github.com/alphadose/haxmap v1.4.1
	github.com/go-jose/go-jose/v4 v4.0.5
	github.com/goccy/go-yaml v1.17.1
	github.com/google/cel-go v0.25.0
	github.com/itchyny/gojq v0.12.17
	github.com/pires/go-proxyproto v0.8.0
	github.com/prometheus/client_golang v1.22.0
	github.com/tetratelabs/wazero v1.9.0
	github.com/yl2chen/cidranger v1.0.2
	golang.org/x/crypto v0.33.0
	golang.org/x/net v0.37.0
)

require (
	cel.dev/expr v0.23.1 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/itchyny/timefmt-go v0.1.6 // indirect
	github.com/kevinpollet/nego v0.0.0-20211010160919-a65cd48cee43 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.63.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/stoewer/go-strcase v1.3.0 // indirect
	golang.org/x/exp v0.0.0-20250210185358-939b2ce775ac // indirect
	golang.org/x/sys v0.30.0 // indirect
	golang.org/x/text v0.22.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240826202546-f6391c0de4c7 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240826202546-f6391c0de4c7 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)

// Pin latest versions to support Go 1.22 to prevent a package update from changing them
// TODO: remove this when Go 1.22+ is supported by other downstream users
replace (
	github.com/go-jose/go-jose/v4 => github.com/go-jose/go-jose/v4 v4.0.5
	github.com/prometheus/procfs => github.com/prometheus/procfs v0.15.1
	golang.org/x/crypto => golang.org/x/crypto v0.33.0
	golang.org/x/exp => golang.org/x/exp v0.0.0-20250210185358-939b2ce775ac
	golang.org/x/net => golang.org/x/net v0.35.0
	golang.org/x/sys => golang.org/x/sys v0.30.0
	golang.org/x/text => golang.org/x/text v0.22.0
	google.golang.org/genproto/googleapis/api => google.golang.org/genproto/googleapis/api v0.0.0-20240826202546-f6391c0de4c7
	google.golang.org/genproto/googleapis/rpc => google.golang.org/genproto/googleapis/rpc v0.0.0-20240826202546-f6391c0de4c7
)
