// Pipeline CI/CD NetDevOps : lint -> qualité -> build -> sécurité -> test -> prod
pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }

    triggers {
        pollSCM('H/5 * * * *')   // à remplacer par un webhook Git si possible
    }

    environment {
        IMAGES = 'netdevops/router-fw:latest netdevops/web-dmz:latest netdevops/dns-lan:latest netdevops/client:latest netdevops/router-fw:test netdevops/web-dmz:test netdevops/dns-lan:test netdevops/client:test'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                sh 'mkdir -p reports'
            }
        }

        stage('Lint') {
            steps {
                sh '''
                    yamllint -c .yamllint .
                    cd ansible && ansible-lint
                    cd .. && pylint scripts
                '''
            }
        }

        stage('SonarQube') {
            steps {
                withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                    sh '''
                        set -e

                        echo "===== TESTS UNITAIRES ====="
                        python3 -m coverage run --branch --source=scripts.check_stack -m unittest discover -s tests -v

                        echo "===== RAPPORT DE COUVERTURE ====="
                        python3 -m coverage report -m
                        python3 -m coverage xml -o coverage.xml

                        echo "===== ANALYSE SONARQUBE ====="
                        sonar-scanner -Dsonar.host.url=http://sonarqube:9000 -Dsonar.token="$SONAR_TOKEN"
                    '''
                }
            }
        }

        stage('Build Docker') {
            steps {
                sh '''
                    set -e
                    echo "===== BUILD IMAGES PRODUCTION ====="
                    docker compose build

                    echo "===== BUILD IMAGES TEST ====="
                    GRAFANA_ADMIN_PASSWORD=build-placeholder docker compose \
                        -p netdevops-test \
                        -f docker-compose.test.yml \
                        -f docker-compose.test.monitoring.yml \
                        --env-file /dev/null build
                '''
            }
        }

        stage('Trivy') {
            steps {
                sh '''
                    for img in $IMAGES; do
                        name=$(echo "$img" | tr '/:' '__')
                        trivy image --no-progress --ignore-unfixed --severity CRITICAL \
                            --exit-code 1 --format table -o "reports/trivy-$name.txt" "$img"
                    done
                '''
            }
        }

        stage('Déploiement TEST + tests') {
            steps {
                withCredentials([file(credentialsId: 'vault-pass', variable: 'VAULT_PASS_FILE')]) {
                    sh '''
                        set -e
                        echo "===== DÉPLOIEMENT ENVIRONNEMENT TEST ====="
                        cd ansible
                        ansible-playbook playbooks/site.yml \
                            --vault-password-file "$VAULT_PASS_FILE" \
                            --extra-vars @environments/test.yml
                        cd ..

                        mkdir -p reports
                        export NETDEVOPS_TEST_HOST=172.18.0.1
                        export NETDEVOPS_WEB_IP=172.21.1.10
                        export NETDEVOPS_DNS_IP=172.21.2.10
                        export NETDEVOPS_MGMT_IP=172.21.3.10
                        export NETDEVOPS_ROUTER_CONTAINER=router-fw-test
                        export NETDEVOPS_WEB_CONTAINER=web-dmz-test
                        export NETDEVOPS_CLIENT_CONTAINER=client-1-test
                        export NETDEVOPS_PROMETHEUS_CONTAINER=prometheus-test
                        export NETDEVOPS_HTTP_PORT=18080
                        export NETDEVOPS_HTTPS_PORT=18443
                        export NETDEVOPS_PROMETHEUS_PORT=9090
                        export NETDEVOPS_DOMAIN=pme.local

                        echo "===== TESTS DE CONNECTIVITÉ TEST ====="
                        if python3 scripts/check_stack.py > reports/tests-connectivite-test.txt 2>&1; then
                            test_status=0
                        else
                            test_status=$?
                        fi

                        cat reports/tests-connectivite-test.txt
                        exit "$test_status"
                    '''
                }
            }
        }

        stage('Déploiement prod') {
            when { branch 'main' }
            steps {
                input message: 'Tous les tests de TEST sont passés. Autoriser le déploiement en PRODUCTION ?'
                withCredentials([file(credentialsId: 'vault-pass', variable: 'VAULT_PASS_FILE')]) {
                    sh 'cd ansible && ansible-playbook playbooks/site.yml --vault-password-file "$VAULT_PASS_FILE"'
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/*', allowEmptyArchive: true
        }
        failure {
            echo "ÉCHEC du pipeline : consulter ${env.BUILD_URL}"
        }
    }
}
