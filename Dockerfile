FROM golang:latest
ADD . /go/src/github.com/smolveau/gotmpcrypt
WORKDIR /go/src/github.com/smolveau/gotmpcrypt
RUN go get ./...
RUN go build -o main .
# Run the outyet command by default when the container starts.
ENTRYPOINT /go/src/github.com/smolveau/gotmpcrypt/main
# Document that the service listens on port 8080.
EXPOSE 9090
