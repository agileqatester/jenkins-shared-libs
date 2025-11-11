def call(String image, String dockerArgs = '', Closure body) {
  // Run steps inside a language SDK container
  docker.image(image).inside(dockerArgs) { body() } // Jenkins Docker Pipeline pattern
}