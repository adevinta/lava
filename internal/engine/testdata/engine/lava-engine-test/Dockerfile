FROM golang:1.21.1-alpine3.18 as build
WORKDIR /go/src/lava-engine-test/
COPY . .
RUN go build

FROM alpine:3.18
COPY --from=build /go/src/lava-engine-test/lava-engine-test /
CMD ["/lava-engine-test"]
