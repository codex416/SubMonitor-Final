FROM nginx:alpine

# acme.sh requires OpenSSL to create the ACME account key and certificates.
# Install curl and CA certificates explicitly as ACME dependencies as well.
RUN apk add --no-cache openssl curl ca-certificates \
    && update-ca-certificates
