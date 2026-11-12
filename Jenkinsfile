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
        COMPOSE = 'docker compose -f docker-compose.yml -f docker-compose.monitoring.yml'
        IMAGES  = 'netdevops/router-fw:latest netdevops/web-dmz:latest netdevops/dns-lan:latest netdevops/client:latest'
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
                    sh 'sonar-scanner -Dsonar.host.url=http://sonarqube:9000 -Dsonar.token=$SONAR_TOKEN'
                }
            }
        }

        stage('Build Docker') {
            steps {
                sh 'docker compose build'
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

        stage('Déploiement test + tests') {
            steps {
                withCredentials([file(credentialsId: 'vault-pass', variable: 'VAULT_PASS_FILE')]) {
                    sh '''
                        cd ansible
                        ansible-playbook playbooks/site.yml --vault-password-file "$VAULT_PASS_FILE"
                        cd ..
                        python3 scripts/check_stack.py | tee reports/tests-connectivite.txt
                    '''
                }
            }
        }

        stage('Déploiement prod') {
            when { branch 'main' }
            steps {
                input message: 'Tous les tests sont passés. Déployer en production ?'
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
