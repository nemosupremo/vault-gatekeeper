FROM golang:alpine

ENV GIN_MODE release
RUN apk add --update git bash && rm -rf /var/cache/apk/*
RUN go get -d github.com/channelmeter/vault-gatekeeper-mesos && \
	cd $GOPATH/src/github.com/channelmeter/vault-gatekeeper-mesos && \
	git checkout tags/0.5.3
RUN cd $GOPATH/src/github.com/channelmeter/vault-gatekeeper-mesos && \
	/bin/bash ./build.bash && cp ./vltgatekeeper /bin/vltgatekeeper

EXPOSE 9201

ENTRYPOINT ["/bin/vltgatekeeper"]
