FROM golang:1.21.1-alpine3.18 as build
WORKDIR /go/src/lava-run-test/
COPY . .
RUN go build

FROM alpine:3.18
COPY --from=build /go/src/lava-run-test/lava-run-test /
USER nobody
CMD ["/lava-run-test"]
