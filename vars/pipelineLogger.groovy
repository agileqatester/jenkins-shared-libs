// vars/pipelineLogger.groovy
def call(String level, String message, Map context = [:]) {
    String timestamp = new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'", TimeZone.getTimeZone('UTC'))
    String contextStr = context ? " | ${context.collect { k, v -> "${k}=${v}" }.join(', ')}" : ''
    
    String logLine = "[${timestamp}] [${level}] ${message}${contextStr}"
    
    switch(level) {
        case 'ERROR':
            error(logLine)
            break
        case 'WARN':
            echo "⚠️  ${logLine}"
            break
        case 'INFO':
            echo "ℹ️  ${logLine}"
            break
        case 'DEBUG':
            if (env.DEBUG_MODE == 'true') {
                echo "🔍 ${logLine}"
            }
            break
    }
}

// Usage in vars:
//pipelineLogger('INFO', 'Starting Docker build', [image: repo, tag: tag])