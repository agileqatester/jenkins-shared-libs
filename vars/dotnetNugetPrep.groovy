/**
 * Ensures the NuGet home directory mounted into the container is present and
 * owned by the expected user (default: uid=1000, gid=1000). This prevents .NET CLI
 * errors like "Access to the path '~/.nuget/NuGet/NuGet.Config' is denied."
 *
 * Typical usage (in Jenkinsfile):
 *   dotnetNugetPrep(
 *     image: 'agileqa/jenkins-agent:multi-tool',
 *     dockerArgs: dockerArgs,                           // must include "-v <host>:/home/jenkins/.nuget"
 *     nugetHomeHost: "${env.WORKSPACE}/.nuget",         // host-side path that is bind-mounted
 *     nugetHomeContainer: '/home/jenkins/.nuget',       // container-side path (default)
 *     uid: 1000,                                        // user id to own the dir
 *     gid: 1000                                         // group id to own the dir
 *   )
 */
def call(Map cfg = [:]) {
    String image              = cfg.get('image', null)
    String dockerArgs         = cfg.get('dockerArgs', '')
    String nugetHomeHost      = cfg.get('nugetHomeHost', '')
    String nugetHomeContainer = cfg.get('nugetHomeContainer', '/home/jenkins/.nuget')
    int uid                   = (cfg.get('uid', 1000) as int)
    int gid                   = (cfg.get('gid', 1000) as int)

    if (!image) {
        error "[dotnetNugetPrep] 'image' is required."
    }
    if (!nugetHomeHost) {
        error "[dotnetNugetPrep] 'nugetHomeHost' (host-side path) is required."
    }
    if (!dockerArgs?.contains("${nugetHomeHost}:${nugetHomeContainer}")) {
        echo "[dotnetNugetPrep] WARNING: dockerArgs does not appear to mount ${nugetHomeHost} to ${nugetHomeContainer}. " +
             "Make sure you include: -v ${nugetHomeHost}:${nugetHomeContainer}"
    }

    // Ensure host-side dirs exist before we enter the container
    sh '''
      set -eux
      mkdir -p '${nugetHomeHost}/NuGet' '${nugetHomeHost}/packages'
    '''

    // Run a short root session INSIDE the build image with the same dockerArgs
    // to fix ownership of the mounted directory.
    docker.image(image).inside("--user 0 ${dockerArgs}") {
        sh '''
          set -eux
          # Make sure container path exists (the mount should create it, but just in case)
          mkdir -p '${nugetHomeContainer}/NuGet' '${nugetHomeContainer}/packages'
          chown -R ${uid}:${gid} '${nugetHomeContainer}'
          ls -ld '${nugetHomeContainer}' '${nugetHomeContainer}/NuGet' '${nugetHomeContainer}/packages'
        '''
    }

    echo "[dotnetNugetPrep] NuGet home prepared at host '${nugetHomeHost}' " +
         "mounted to container '${nugetHomeContainer}' and owned by ${uid}:${gid}."
}