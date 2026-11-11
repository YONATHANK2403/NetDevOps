FROM jenkins/jenkins:lts-jdk17
USER root

# Outils de lint et d'automatisation
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3-pip unzip curl openssl \
 && pip3 install --no-cache-dir --break-system-packages ansible-core ansible-lint yamllint pylint \
 && rm -rf /var/lib/apt/lists/*

# Docker CLI + plugin Compose (le démon reste celui de l'hôte, via le socket)
COPY --from=docker:27-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker:27-cli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose

# Trivy (scan de vulnérabilités) et SonarScanner (analyse statique)
ARG TRIVY_VERSION=0.58.0
ARG SONAR_SCANNER_VERSION=6.2.1.4610
RUN curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v${TRIVY_VERSION} \
 && curl -sSfLo /tmp/sonar.zip https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}-linux-x64.zip \
 && unzip -q /tmp/sonar.zip -d /opt \
 && ln -s /opt/sonar-scanner-${SONAR_SCANNER_VERSION}-linux-x64/bin/sonar-scanner /usr/local/bin/sonar-scanner \
 && rm /tmp/sonar.zip

COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt
