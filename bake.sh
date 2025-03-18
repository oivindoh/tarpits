#!/bin/bash
export DOCKER_IMG_REPO=$(git config --local remote.origin.url|sed -n 's#.*:\([^.]*\)\/.*\.git#\1#p')
export DOCKER_IMG_N=$(git config --local remote.origin.url|sed -n 's#.*/\([^.]*\)\.git#\1#p')
export DOCKER_IMG_TAG=$(git rev-parse HEAD | cut -c1-7)


docker buildx create --driver docker-container --platform 'linux/amd64' --name home
buildxcreate=$?
echo "exited ${buildxcreate}"
if [ $buildxcreate -eq 1 ]; then
    echo "Trying to use home buildx env"
    docker buildx use home
    useexit=$?

    if [ $useexit -eq 0 ]; then
        docker buildx bake --progress=plain --provenance true --sbom true -f bake.hcl --push
    fi
fi

echo ${DOCKER_IMG_REPO}
echo ${DOCKER_IMG_N}
echo ${DOCKER_IMG_TAG}
docker buildx bake -f bake.hcl --push
