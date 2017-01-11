FROM golang:alpine

ENV GIN_MODE release

RUN apk add --update git bash && \
    rm -rf /var/cache/apk/* && \
    go get -d github.com/channelmeter/vault-gatekeeper-mesos && \
    cd $GOPATH/src/github.com/channelmeter/vault-gatekeeper-mesos && \
    git checkout tags/0.5.3 && \
    /bin/bash ./build.bash && \
    cp ./vltgatekeeper /bin/vltgatekeeper && \
    rm -r $GOPATH/src/github.com/channelmeter/vault-gatekeeper-mesos && \
    apk del git

EXPOSE 9201

ENTRYPOINT ["/bin/vltgatekeeper"]
