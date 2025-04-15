// yaml_stream.jsonnet
local Build(go, alpine, os, arch) = {
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
    },
    steps: [
        {
            name: "build",
            image: "golang:" + go +"-alpine" + alpine,
            commands: [
                "apk update",
                "apk add --no-cache git",
                "mkdir .bin",
                "go build -v -o ./.bin/go-away ./cmd/go-away",
                "go build -v -o ./.bin/test-wasm-runtime ./cmd/test-wasm-runtime",
            ],
        },
        {
            name: "test-wasm-success",
            image: "alpine:" + alpine,
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

local Publish(go, alpine, os, arch, trigger, platforms, extra) = {
    kind: "pipeline",
    type: "docker",
    name: "publish-" + go + "-alpine" + alpine,
    platform: {
        os: os,
        arch: arch,
    },
    trigger: trigger,
    steps: [
        {
            name: "docker",
            image: "plugins/buildx",
            privileged: true,
            environment: {
                DOCKER_BUILDKIT: "1"
            },
            settings: {
                  registry: "git.gammaspectra.live",
                  repo: "git.gammaspectra.live/git/go-away",
                  compress: true,
                  platform: platforms,
                  builder_driver: "docker-container",
                  build_args: {
                    from_builder: "golang:" + go +"-alpine" + alpine,
                    from: "alpine:" + alpine,
                  },
                  auto_tag_suffix: "alpine" + alpine,
                  username: {
                    from_secret: "git_username",
                  },
                  password: {
                    from_secret: "git_password",
                  },
            } + extra,
        },
    ]
};

#

[
    Build("1.22", "3.20", "linux", "amd64"),
    Build("1.22", "3.20", "linux", "arm64"),
]