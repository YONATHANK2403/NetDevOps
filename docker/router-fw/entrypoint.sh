#!/bin/sh
# Charge les règles nftables puis garde le conteneur actif.
set -eu
nft -f /etc/nftables.conf
echo "[router-fw] règles nftables chargées"
exec tail -f /dev/null
