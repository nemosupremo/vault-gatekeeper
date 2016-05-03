FROM golang:alpine

ENV GIN_MODE release
RUN apk add --update git bash && rm -rf /var/cache/apk/*
RUN go get -d github.com/channelmeter/vault-gatekeeper-mesos
RUN cd $GOPATH/src/github.com/channelmeter/vault-gatekeeper-mesos && git checkout tags/0.0.4 && /bin/bash ./build.bash && cp ./vltgatekeeper /bin/vltgatekeeper

EXPOSE 9201

ENTRYPOINT ["/bin/vltgatekeeper"]