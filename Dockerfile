# Step 1: Fetch certificates and timezone data
FROM --platform=$BUILDPLATFORM alpine:3.19 AS certs
RUN apk add --no-cache ca-certificates tzdata

# Step 2: Build the minimal scratch image
FROM scratch

# Copy certificates and timezone info
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=certs /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the binary built by GoReleaser
COPY road-1337 /road-1337

# Expose entrypoint
ENTRYPOINT ["/road-1337"]
CMD ["server", "--port", "1337"]
