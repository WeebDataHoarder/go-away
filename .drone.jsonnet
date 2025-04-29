// yaml_stream.jsonnet
local Build(mirror, go, alpine, os, arch) = {
    kind: "pipeline",
    type: "docker",
    name: "build-" + go + "-alpine" + alpine + "-" + arch,
    platform: {
        os: os,
        arch: arch
    },
    environment: {
        GOTOOLCHAIN: "local",
        CGO_ENABLED: "0",
        GOOS: os,
        GOARCH: arch,
        GORACE: "halt_on_error=1"
    },
    steps: [
        {
            name: "build",
            image: "golang:" + go +"-alpine" + alpine,
            mirror: mirror,
            commands: [
                "apk update",
                "apk add --no-cache git",
                "mkdir .bin",
                "go build -v -pgo=auto -v -trimpath -ldflags=-buildid= -o ./.bin/go-away ./cmd/go-away",
                "go build -v -o ./.bin/test-wasm-runtime ./cmd/test-wasm-runtime",
            ],
        },
        {
            name: "test",
            image: "golang:" + go +"-alpine" + alpine,
            mirror: mirror,
            commands: [
                "apk update",
                "apk add --no-cache git",
                "go test -p 1 -timeout 20m -v  ./tests/"
            ],
        },
        {
            name: "check-policy-forgejo",
            image: "alpine:" + alpine,
            mirror: mirror,
            depends_on: ["build"],
            commands: [
                "./.bin/go-away --check --slog-level DEBUG --backend example.com=http://127.0.0.1:80 --policy examples/forgejo.yml --policy-snippets examples/snippets/"
            ],
        },
        {
            name: "check-policy-generic",
            image: "alpine:" + alpine,
            mirror: mirror,
            depends_on: ["build"],
            commands: [
                "./.bin/go-away --check --slog-level DEBUG --backend example.com=http://127.0.0.1:80 --policy examples/generic.yml --policy-snippets examples/snippets/"
            ],
        },
        {
            name: "check-policy-spa",
            image: "alpine:" + alpine,
            mirror: mirror,
            depends_on: ["build"],
            commands: [
                "./.bin/go-away --check --slog-level DEBUG --backend example.com=http://127.0.0.1:80 --policy examples/spa.yml --policy-snippets examples/snippets/"
            ],
        },
        {
            name: "test-wasm-success",
            image: "alpine:" + alpine,
            mirror: mirror,
            depends_on: ["build"],
            commands: [
                "./.bin/test-wasm-runtime -wasm ./embed/challenge/js-pow-sha256/runtime/runtime.wasm " +
                "-make-challenge ./embed/challenge/js-pow-sha256/test/make-challenge.json " +
                "-make-challenge-out ./embed/challenge/js-pow-sha256/test/make-challenge-out.json " +
                "-verify-challenge ./embed/challenge/js-pow-sha256/test/verify-challenge.json " +
                "-verify-challenge-out 0",
            ],
        },
        {
            name: "test-wasm-fail",
            image: "alpine:" + alpine,
            mirror: mirror,
            depends_on: ["build"],
            commands: [
                "./.bin/test-wasm-runtime -wasm ./embed/challenge/js-pow-sha256/runtime/runtime.wasm " +
                "-make-challenge ./embed/challenge/js-pow-sha256/test/make-challenge.json " +
                "-make-challenge-out ./embed/challenge/js-pow-sha256/test/make-challenge-out.json " +
                "-verify-challenge ./embed/challenge/js-pow-sha256/test/verify-challenge-fail.json " +
                "-verify-challenge-out 1",
            ],
        },
    ]
};

local Publish(mirror, registry, repo, secret, go, alpine, os, arch, trigger, platforms, extra) = {
    kind: "pipeline",
    type: "docker",
    name: "publish-" + go + "-alpine" + alpine + "-" + secret,
    platform: {
        os: os,
        arch: arch,
    },
    trigger: trigger,
    steps: [
        {
            name: "test",
            image: "golang:" + go +"-alpine" + alpine,
            mirror: mirror,
            commands: [
                "apk update",
                "apk add --no-cache git",
                "go test -p 1 -timeout 20m -v  ./tests/"
            ],
        },
        {
            name: "setup-buildkitd",
            image: "alpine:" + alpine,
            mirror: mirror,
            commands: [
                "echo '[registry.\"docker.io\"]' > buildkitd.toml",
                "echo '  mirrors = [\"mirror.gcr.io\"]' >> buildkitd.toml"
            ],
        },
        {
            name: "docker",
            image: "plugins/buildx",
            privileged: true,
            environment: {
                DOCKER_BUILDKIT: "1",
                SOURCE_DATE_EPOCH: 0,
                TZ: "UTC",
                LC_ALL: "C",
                PLUGIN_BUILDER_CONFIG: "buildkitd.toml",
                PLUGIN_BUILDER_DRIVER: "docker-container",
            },
            settings: {
                  registry: registry,
                  repo: repo,
                  mirror: mirror,
                  compress: true,
                  platform: platforms,
                  build_args: {
                    from_builder: "golang:" + go +"-alpine" + alpine,
                    from: "alpine:" + alpine,
                  },
                  auto_tag_suffix: "alpine" + alpine,
                  username: {
                    from_secret: secret + "_username",
                  },
                  password: {
                    from_secret: secret + "_password",
                  },
            } + extra,
        },
    ]
};

#
local containerArchitectures = ["linux/amd64", "linux/arm64", "linux/riscv64"];

local alpineVersion = "3.21";
local goVersion = "1.24";

local mirror = "https://mirror.gcr.io";

[
    Build(mirror, goVersion, alpineVersion, "linux", "amd64"),
    Build(mirror, goVersion, alpineVersion, "linux", "arm64"),

    # latest
    Publish(mirror, "git.gammaspectra.live", "git.gammaspectra.live/git/go-away", "git", goVersion, alpineVersion, "linux", "amd64", {event: ["push"], branch: ["master"], }, containerArchitectures, {tags: ["latest"],}) + {name: "publish-latest-git"},
    Publish(mirror, "codeberg.org", "codeberg.org/gone/go-away", "codeberg", goVersion, alpineVersion, "linux", "amd64", {event: ["push"], branch: ["master"], }, containerArchitectures, {tags: ["latest"],}) + {name: "publish-latest-codeberg"},
    Publish(mirror, "ghcr.io", "ghcr.io/weebdatahoarder/go-away", "github", goVersion, alpineVersion, "linux", "amd64", {event: ["push"], branch: ["master"], }, containerArchitectures, {tags: ["latest"],}) + {name: "publish-latest-github"},

    # modern
    Publish(mirror, "git.gammaspectra.live", "git.gammaspectra.live/git/go-away", "git", goVersion, alpineVersion, "linux", "amd64", {event: ["promote", "tag"], target: ["production"], }, containerArchitectures, {auto_tag: true,}),
    Publish(mirror, "codeberg.org", "codeberg.org/gone/go-away", "codeberg", goVersion, alpineVersion, "linux", "amd64", {event: ["promote", "tag"], target: ["production"], }, containerArchitectures, {auto_tag: true,}),
    Publish(mirror, "ghcr.io", "ghcr.io/weebdatahoarder/go-away", "github", goVersion, alpineVersion, "linux", "amd64", {event: ["promote", "tag"], target: ["production"], }, containerArchitectures, {auto_tag: true,}),
]