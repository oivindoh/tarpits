variable "PLATFORMS" {
  default = ["linux/amd64", "linux/arm64"]
}

variable "DOCKER_IMG_SSH" {
  default = "ssh-tarpit"
}

variable "DOCKER_IMG_HTTP" {
  default = "http-tarpit"
}

variable "DOCKER_IMG_UPDATER" {
  default = "ssh-tarpit-policy-updater"
}

variable "DOCKER_IMG_TAG" {
  default = null
}

variable "DOCKER_IMG_REPO" {
  default = null
}

group "default" {
  targets = [
    "http-tarpit",
    "ssh-tarpit",
    "ssh-tarpit-policy-updater"
  ]
}

target "http-tarpit" {
  context = "./http"
  dockerfile = "Dockerfile"
  tags = ["${DOCKER_IMG_REPO}/${DOCKER_IMG_HTTP}:latest", "${DOCKER_IMG_REPO}/${DOCKER_IMG_HTTP}:${DOCKER_IMG_TAG}"]
  args = {
  }
  platforms = "${PLATFORMS}"
}


target "ssh-tarpit" {
  context = "./ssh"
  dockerfile = "Dockerfile"
  tags = ["${DOCKER_IMG_REPO}/${DOCKER_IMG_SSH}:latest", "${DOCKER_IMG_REPO}/${DOCKER_IMG_SSH}:${DOCKER_IMG_TAG}"]
  args = {
  }
  platforms = "${PLATFORMS}"
}

target "ssh-tarpit-policy-updater" {
  context = "./policy"
  dockerfile = "Dockerfile"
  tags = ["${DOCKER_IMG_REPO}/${DOCKER_IMG_UPDATER}:latest", "${DOCKER_IMG_REPO}/${DOCKER_IMG_UPDATER}:${DOCKER_IMG_TAG}"]
  args = {
  }
  platforms = "${PLATFORMS}"
}
