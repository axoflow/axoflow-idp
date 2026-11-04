FROM --platform=$BUILDPLATFORM golang:1.26.10-alpine3.24@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308 AS builder

ARG TARGETOS
ARG TARGETARCH
ARG GO_BUILD_FLAGS

WORKDIR /usr/local/src/axoidp

COPY go.mod go.mod
COPY go.sum go.sum

# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

COPY main.go main.go
COPY internal/ internal/
COPY pkg/ pkg/
COPY templates/ templates/

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build $GO_BUILD_FLAGS -o /usr/local/bin/axoidp

FROM builder AS debug

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go install github.com/go-delve/delve/cmd/dlv@latest

CMD ["/go/bin/dlv", "--listen=:40000", "--headless=true", "--api-version=2", "--accept-multiclient", "exec", "/usr/local/bin/axoidp"]

FROM gcr.io/distroless/static:latest@sha256:9197324ba51d9cd071af8505989365c006adf9d6d2067eada25aef00abbb5278

COPY --from=builder /usr/local/bin/axoidp /axoidp
COPY --from=builder /usr/local/src/axoidp/templates /templates

ENTRYPOINT ["/axoidp"]
