ARG from_builder=golang:1.24-alpine3.21
ARG from=alpine:3.21

ARG BUILDPLATFORM

FROM --platform=$BUILDPLATFORM ${from_builder} AS build

ARG TARGETARCH
ARG TARGETOS
ARG GOTOOLCHAIN=local

RUN apk update && apk add --no-cache \
    bash \
    git \
    zopfli brotli zstd

ENV GOBIN="/go/bin"

COPY . .

RUN ./build-compress.sh

ENV CGO_ENABLED=0
ENV GOOS=${TARGETOS}
ENV GOARCH=${TARGETARCH}
ENV GOTOOLCHAIN=${GOTOOLCHAIN}

RUN go build -pgo=auto -v -trimpath -o "${GOBIN}/go-away" ./cmd/go-away
RUN test -e "${GOBIN}/go-away"


FROM --platform=$TARGETPLATFORM ${from}

COPY --from=build /go/bin/go-away /bin/go-away

ENV TZ UTC

ENV GOAWAY_BIND=":8080"
ENV GOAWAY_BIND_NETWORK="tcp"
ENV GOAWAY_SOCKET_MODE="0770"
ENV GOAWAY_POLICY="/policy.yml"
ENV GOAWAY_CHALLENGE_TEMPLATE="anubis"
ENV GOAWAY_CHALLENGE_TEMPLATE_THEME=""
ENV GOAWAY_SLOG_LEVEL="WARN"
ENV GOAWAY_CLIENT_IP_HEADER=""
ENV GOAWAY_BACKEND_IP_HEADER=""
ENV GOAWAY_JWT_PRIVATE_KEY_SEED=""
ENV GOAWAY_BACKEND=""
ENV GOAWAY_DNSBL="dnsbl.dronebl.org"
ENV GOAWAY_ACME_AUTOCERT=""
ENV GOAWAY_CACHE="/cache"

EXPOSE 8080/tcp
EXPOSE 8080/udp

ENV JWT_PRIVATE_KEY_SEED="${GOAWAY_JWT_PRIVATE_KEY_SEED}"

ENTRYPOINT  /bin/go-away --bind "${GOAWAY_BIND}" --bind-network "${GOAWAY_BIND_NETWORK}" --socket-mode "${GOAWAY_SOCKET_MODE}" \
            --policy ${GOAWAY_POLICY} --client-ip-header "${GOAWAY_CLIENT_IP_HEADER}" --backend-ip-header "${GOAWAY_BACKEND_IP_HEADER}" \
            --cache "${GOAWAY_CACHE}" \
            --dnsbl "${GOAWAY_DNSBL}" \
            --challenge-template "${GOAWAY_CHALLENGE_TEMPLATE}" --challenge-template-theme "${GOAWAY_CHALLENGE_TEMPLATE_THEME}" \
            --slog-level "${GOAWAY_SLOG_LEVEL}" \
            --acme-autocert "${GOAWAY_ACME_AUTOCERT}" \
            --backend "${GOAWAY_BACKEND}"