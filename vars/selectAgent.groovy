def call(String projectType) {
    switch(projectType) {
        case 'node':
            return 'node:18'
        case 'java':
            return 'maven:3.8.6-openjdk-11'
        case 'gradle':
            return 'gradle:7.6-jdk11'
        case 'dotnet':
            return 'mcr.microsoft.com/dotnet/sdk:7.0'
        default:
            error "Unknown project type: ${projectType}"
    }
}
