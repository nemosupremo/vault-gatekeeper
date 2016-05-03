FROM golang:alpine

RUN go get -d github.com/channelmeter/vault-gatekeeper-mesos
RUN cd $GOPATH/src/channelmeter/vault-gatekeeper-mesos && git checkout tags/0.0.1 && ./build.bash && cp ./vltgatekeeper /bin/vltgatekeeper

EXPOSE 9201

ENTRYPOINT ["/bin/vltgatekeeper"]