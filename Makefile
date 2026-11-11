.RECIPEPREFIX = >
COMPOSE = docker compose -f docker-compose.yml -f docker-compose.monitoring.yml

.PHONY: help env certs up down test lint tools-up

help:
> @echo "make up | down | test | lint | tools-up"

env:
> @test -f .env || (cp .env.example .env && echo ".env créé : changez les mots de passe !")

certs:
> @mkdir -p docker/web-dmz/certs
> @test -f docker/web-dmz/certs/selfsigned.crt || openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
>   -subj "/CN=web.pme.local" -keyout docker/web-dmz/certs/selfsigned.key -out docker/web-dmz/certs/selfsigned.crt

up: env certs
> $(COMPOSE) up -d --build

down:
> $(COMPOSE) down

test:
> python3 scripts/check_stack.py

lint:
> yamllint -c .yamllint .
> cd ansible && ansible-lint
> pylint scripts

tools-up: env
> sudo mkdir -p /srv/jenkins_home && sudo chown 1000:1000 /srv/jenkins_home
> docker compose -f docker-compose.tools.yml up -d --build
