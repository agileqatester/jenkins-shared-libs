def call(Map cfg = [:]) {
  if (!cfg.run && params.RUN_TESTS == false) return
  String sdk = cfg.sdk ?: (params.DOTNET_SDK ?: '8.0')
  String testProj = cfg.testProject ?: (params.TEST_PROJECT ?: '')
  withToolImage("mcr.microsoft.com/dotnet/sdk:${sdk}", "-e DOTNET_CLI_TELEMETRY_OPTOUT=1") {
    if (testProj?.trim()) sh "dotnet test '${testProj}' --logger 'trx;LogFileName=test-results.trx'"
    else                  sh "dotnet test --logger 'trx;LogFileName=test-results.trx'"
  }
  junit allowEmptyResults: true, testResults: '**/TestResults/*.trx'
}