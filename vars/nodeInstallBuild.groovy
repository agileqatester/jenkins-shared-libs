def call(Map cfg = [:]) {
  String nodeVer = cfg.node ?: (params.NODE_VERSION ?: '20-alpine')
  String pkgMgr  = (cfg.pkgMgr ?: params.PKG_MGR ?: 'npm').trim()
  String build   = cfg.buildScript ?: (params.BUILD_SCRIPT ?: 'build')
  String cacheArgs = "-v $HOME/.npm:/root/.npm -v $HOME/.cache/yarn:/root/.cache/yarn"

  withToolImage("node:${nodeVer}", cacheArgs) {
    sh "node -v && ${pkgMgr} --version"

    if (pkgMgr == 'npm') {
      // Ensure devDependencies are present even if NODE_ENV=production is set upstream
      sh 'NODE_ENV=development npm ci --include=dev'
      sh 'npx --no-install tsc --version || true'  // optional sanity check
      if (params.RUN_TESTS) sh 'npm test --if-present'
      sh "npm run ${build} --if-present"
    } else {
      sh 'corepack enable || true'
      sh 'yarn install --frozen-lockfile'
      if (params.RUN_TESTS) sh 'yarn test || true'
      sh "yarn ${build} || true"
    }
  }
}