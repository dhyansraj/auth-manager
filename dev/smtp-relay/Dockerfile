FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags='-s -w' -o /relay .

FROM gcr.io/distroless/static-debian12
COPY --from=build /relay /relay
EXPOSE 25
USER 65532:65532
ENTRYPOINT ["/relay"]
