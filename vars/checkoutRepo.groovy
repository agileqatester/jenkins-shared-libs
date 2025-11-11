def call(Map cfg = [:]) {
  def url    = cfg.url    ?: params.GIT_URL
  def branch = cfg.branch ?: params.GIT_BRANCH ?: 'main'
  checkout([$class: 'GitSCM',
    branches: [[name: branch]],
    userRemoteConfigs: [[url: url]],
    extensions: [[$class: 'CloneOption', shallow: true, depth: 3, noTags: false]]
  ])
}