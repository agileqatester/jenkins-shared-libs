// vars/deployToEnvironment.groovy
def call(Map cfg = [:]) {
    String env = cfg.environment ?: error('environment required (dev/staging/prod)')
    String image = cfg.image ?: error('image required')
    String tag = cfg.tag ?: 'latest'
    
    // Load environment-specific config
    def envConfig = readJSON file: "deploy/config/${env}.json"
    
    switch(envConfig.platform) {
        case 'docker':
            deployContainer(
                image: "${image}:${tag}",
                containerName: "${envConfig.appName}_${env}",
                ports: envConfig.ports,
                healthPath: envConfig.healthPath
            )
            break
            
        case 'kubernetes':
            deployToK8s(
                image: "${image}:${tag}",
                namespace: envConfig.namespace,
                helmChart: envConfig.helmChart,
                values: envConfig.helmValues
            )
            break
            
        case 'ecs':
            deployToECS(
                image: "${image}:${tag}",
                cluster: envConfig.cluster,
                service: envConfig.service,
                taskDef: envConfig.taskDefinition
            )
            break
    }
}