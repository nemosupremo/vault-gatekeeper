FROM golang:alpine

ENV GIN_MODE release

COPY . $GOPATH/src/github.com/channelmeter/vault-gatekeeper-mesos

RUN apk add --virtual .build-deps --update git bash &&\
	cd $GOPATH/src/github.com/channelmeter/vault-gatekeeper-mesos &&\
	GOLDFLAGS=-s /bin/bash ./build.bash && cp ./vltgatekeeper /bin/vltgatekeeper &&\
	apk del .build-deps &&\
	eval `go env` && rm -rf /var/cache/apk/* $GOPATH $GOROOT

EXPOSE 9201

ENTRYPOINT ["/bin/vltgatekeeper"]
