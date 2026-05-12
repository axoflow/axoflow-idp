FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine3.22@sha256:be93003ee861b3b91b6ebcb22678524947e0cd786c2df3f32af520006b1e54f5 AS builder

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

FROM gcr.io/distroless/static:latest@sha256:87bce11be0af225e4ca761c40babb06d6d559f5767fbf7dc3c47f0f1a466b92c

COPY --from=builder /usr/local/bin/axoidp /axoidp
COPY --from=builder /usr/local/src/axoidp/templates /templates

ENTRYPOINT ["/axoidp"]
