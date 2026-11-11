#!/bin/sh
# Ajoute les routes vers les autres zones en passant par router-fw.
# Variables : GW (passerelle = router-fw) et ROUTES (liste de réseaux CIDR).
set -eu
for net in ${ROUTES:-}; do
  ip route replace "$net" via "$GW"
  echo "[routes] $net via $GW"
done
