
// Shared Library: vars/selectAgent.groovy
def call(appType) {
    switch(appType) {
        case 'dotnet':
            return 'agileqa/jenkins-agent:multi-tool'
        case 'nodejs':
            return 'node:20'
        case 'python':
            return 'python:3.11'
        case 'java':
            return 'maven:3.9.4-eclipse-temurin-17'
        default:
            error "Unknown app type: ${appType}"
    }
} 