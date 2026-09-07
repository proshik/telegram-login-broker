# distroless/static, not scratch: scratch carries no CA certificates, and the
# broker's telegram mode makes an outbound TLS call to oauth.telegram.org while
# mock mode does not. On scratch the image would work perfectly in mock and fail
# only against real Telegram — a difference that shows up at the worst moment.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
# Static, stripped, reproducible enough to compare two builds by hand.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/broker ./cmd/broker
# An empty /data owned by the runtime user. Docker copies the ownership of an
# existing image directory onto a fresh named volume, and without this the
# nonroot user cannot write the registry into its own volume.
RUN mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/broker /broker
COPY --from=build --chown=65532:65532 /out/data /data
# The registry lives here; mount a volume on it or the configuration dies on the
# first redeploy.
VOLUME ["/data"]
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/broker"]
