def call(String projectType) {
    switch(projectType) {
        case 'node':
            sh 'npm install && npm run build'
            break
        case 'java':
            sh 'mvn clean install'
            break
        case 'gradle':
            sh './gradlew build'
            break
        case 'dotnet':
            sh 'dotnet restore && dotnet build'
            break
        default:
            error "Unknown project type: ${projectType}"
    }
}
