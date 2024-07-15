FROM golang:1.22.5-alpine as dev-env

WORKDIR /app

FROM dev-env as build-env
COPY go.mod /go.sum /app/
RUN go mod download

COPY . /app/

RUN CGO_ENABLED=0 go build -o /breakglass ./cmd/breakglass

FROM alpine:3.20.1 as runtime

COPY --from=build-env /breakglass /usr/local/bin/breakglass
RUN chmod +x /usr/local/bin/breakglass

ENTRYPOINT ["breakglass"]