def call(Map cfg = [:]) {
  String registryUrl   = (cfg.registry ?: params.REGISTRY ?: '') // empty == Docker Hub
  String credsId       = (cfg.credentialsId ?: params.REGISTRY_CREDENTIALS_ID)
  String imageRepo     = cfg.image ?: params.IMAGE_NAME          // e.g. 'agileqa/dotnet-app'
  String tag           = cfg.tag   ?: (params.IMAGE_TAG ?: env.BUILD_NUMBER)
  String context       = cfg.context ?: '.'

  def img = docker.build("${imageRepo}:${tag}", context)
  if (params.PUBLISH_IMAGE?.toString() == 'true' || cfg.push) {
    docker.withRegistry(registryUrl, credsId) {     // Authenticated push
      img.push(tag)
      img.push('latest')
    }
  }
}