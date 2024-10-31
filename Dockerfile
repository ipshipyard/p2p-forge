FROM --platform=${BUILDPLATFORM:-linux/amd64} golang:1.23-bookworm AS builder

LABEL org.opencontainers.image.source=https://github.com/ipshipyard/p2p-forge
LABEL org.opencontainers.image.documentation=https://github.com/ipshipyard/p2p-forge#docker
LABEL org.opencontainers.image.description="An Authoritative DNS server for distributing DNS subdomains to libp2p peers"
# TODO: decide license: LABEL org.opencontainers.image.licenses=MIT+APACHE_2.0


# This builds p2p-forge

ARG TARGETPLATFORM TARGETOS TARGETARCH

ENV GOPATH="/go"
ENV SRC_PATH="$GOPATH/src/github.com/ipshipyard/p2p-forge"
ENV GO111MODULE=on
ENV GOPROXY="https://proxy.golang.org"

COPY go.* $SRC_PATH/
WORKDIR $SRC_PATH
RUN go mod download

COPY . $SRC_PATH
RUN git config --global --add safe.directory /go/src/github.com/ipshipyard/p2p-forge

RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o $GOPATH/bin/p2p-forge

#------------------------------------------------------
FROM debian:bookworm-slim

# Instal binaries for $TARGETARCH
RUN apt-get update && \
  apt-get install --no-install-recommends -y tini ca-certificates libcap2-bin && \
  rm -rf /var/lib/apt/lists/*

ENV GOPATH="/go"
ENV SRC_PATH="$GOPATH/src/github.com/ipshipyard/p2p-forge"
ENV P2P_FORGE_PATH="/p2p-forge"

COPY --from=builder $GOPATH/bin/p2p-forge /usr/local/bin/p2p-forge
COPY --from=builder $SRC_PATH/.github/docker/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN mkdir -p $P2P_FORGE_PATH && \
  useradd -d $P2P_FORGE_PATH -u 1000 -G users p2pforge && \
  chown p2pforge:users $P2P_FORGE_PATH && \
  setcap cap_net_bind_service=+ep /usr/local/bin/p2p-forge

WORKDIR $P2P_FORGE_PATH
USER p2pforge
EXPOSE 53 53/udp
EXPOSE 9253
ENTRYPOINT ["tini", "--", "/usr/local/bin/entrypoint.sh"]
