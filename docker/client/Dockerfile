FROM alpine:3.20

RUN apk add --no-cache \
    curl \
    bind-tools \
    netcat-openbsd \
    iproute2

# Processus applicatif non privilégié par défaut
USER nobody
