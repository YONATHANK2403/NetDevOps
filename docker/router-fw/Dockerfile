FROM alpine:3.20
RUN apk add --no-cache nftables
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]

# Utilisateur non privilégié par défaut
USER nobody
