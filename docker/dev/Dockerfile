FROM golang:alpine3.20 AS builder

WORKDIR /app

RUN go install github.com/air-verse/air@latest

COPY go.mod ./
COPY go.sum ./

RUN go mod download && go mod verify

VOLUME ["/app"]

EXPOSE 5000