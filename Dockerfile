# Step 1: Fetch certificates 
FROM alpine:3.19 AS certs
RUN apk add --no-cache ca-certificates tzdata

# Step 2: The actual minimal image (0 bytes overhead)
FROM scratch

# Copy certs from the previous stage
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=certs /usr/share/zoneinfo /usr/share/zoneinfo

# GoReleaser will inject the binary here
COPY road-1337 /road-1337

# Set the entrypoint
ENTRYPOINT ["/road-1337"]
CMD ["server", "--port", "1337"]
