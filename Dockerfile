FROM golang:1.10
ARG DEP_VERSION=v0.4.1
RUN curl -fsSL -o /usr/local/bin/dep https://github.com/golang/dep/releases/download/${DEP_VERSION}/dep-linux-amd64 && chmod +x /usr/local/bin/dep
WORKDIR /go/src/github.com/nemosupremo/vault-gatekeeper/
COPY ./ ./
RUN mkdir -p $GOPATH/pkg && dep ensure -v -vendor-only && \
	CGO_ENABLED=0 go build -ldflags "-X main.BuildTime=`date -u '+%Y-%m-%d_%I:%M:%S%p'` -X main.Version=`git -C ./ describe --abbrev=0 --tags HEAD`" -a -installsuffix cgo -o dist/gatekeeper ./cmd/gatekeeper

FROM scratch
COPY --from=0 /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=0 /go/src/github.com/nemosupremo/vault-gatekeeper/dist/gatekeeper /
# Create the /tmp directory
WORKDIR /tmp
WORKDIR /
ENTRYPOINT ["/gatekeeper"]
CMD ["server"]