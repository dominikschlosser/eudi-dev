FROM golang:1.26-alpine AS build
ARG VERSION=dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -ldflags "-s -w -X github.com/dominikschlosser/eudi-dev/cmd.Version=${VERSION}" -o eudi .

FROM alpine:3.21
RUN adduser -D -h /home/app app
COPY --from=build /app/eudi /usr/local/bin/
# Legacy binary name keeps working for the time being
RUN ln -s /usr/local/bin/eudi /usr/local/bin/oid4vc-dev
USER app
ENV PORT=8085
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -q --spider http://localhost:${PORT}/ || exit 1
ENTRYPOINT ["eudi"]
CMD ["wallet", "serve", "--auto-accept", "--pid", "--port", "8085"]
