@Library('jenkins-shared-library') _
pipeline {
    agent {
        docker {
            image selectAgent('dotnet')
        }
    }
    stages {
        stage('Build') {
            steps {
                runBuild('dotnet')
            }
        }
    }
}
