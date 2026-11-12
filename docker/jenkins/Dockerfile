FROM jenkins/jenkins:lts-jdk21

USER root

# Outils de lint et d'automatisation
RUN set -eux; \
    find /etc/apt -type f \( -name '*.sources' -o -name '*.list' \) \
      -exec sed -i 's#http://deb.debian.org#https://deb.debian.org#g' {} +; \
    apt-get -o Acquire::Retries=3 update; \
    apt-get install -y --no-install-recommends \
      python3-pip \
      unzip \
      curl \
      openssl \
      ca-certificates; \
    pip3 install --no-cache-dir --break-system-packages \
      ansible-core \
      ansible-lint \
      yamllint \
      pylint; \
    rm -rf /var/lib/apt/lists/*

# Docker CLI et plugin Compose
COPY --from=docker:27-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker:27-cli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose

# Trivy et SonarScanner
# Trivy depuis l'image officielle
COPY --from=aquasec/trivy:0.58.2 /usr/local/bin/trivy /usr/local/bin/trivy

# Installation de SonarScanner
ARG SONAR_SCANNER_VERSION=6.2.1.4610

RUN curl -fsSLo /tmp/sonar.zip \
    https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-${SONAR_SCANNER_VERSION}-linux-x64.zip \
 && unzip -q /tmp/sonar.zip -d /opt \
 && ln -s /opt/sonar-scanner-${SONAR_SCANNER_VERSION}-linux-x64/bin/sonar-scanner /usr/local/bin/sonar-scanner \
 && rm /tmp/sonar.zip

# Plugins Jenkins
COPY plugins.txt /usr/share/jenkins/ref/plugins.txt

RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt

# Exécution sans privilèges root
USER jenkins
