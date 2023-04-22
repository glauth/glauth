#!/bin/bash

inform() {
    echo "--------------------------------------------------------------------------------"
    echo "$@"
    echo "--------------------------------------------------------------------------------"
}

image_name() {
    [[ "$1" == "plugins" ]] && { echo "glauth-plugins"; } || { echo "glauth"; }
}

ldap_port() {
    [[ "$1" == "plugins" ]] && { echo "3893"; } || { echo "3893"; }
}

prepare_image() {
    profile="$1"
    img="localhost/$(image_name $profile)"

    inform "Deleting local builds to avoid future surprises."
    rm -rf bin
    inform "Mounting pseudo app directory to expose parent to current context."
    mkdir -p local/app
    sudo mount -o bind .. local/app/
    inform "Building profile: $profile container: $img"
    podman build --security-opt seccomp=scripts/docker/fastat-workaround.json -f Dockerfile-$profile -t $img
    sudo umount local/app

    inform "Starting registry"
    mkdir -p local/registry
    podman run -d --name registry -p 5000:5000 -v ./local/registry:/var/lib/registry --restart=unless-stopped registry:2

    inform "Pushing image to container"
    podman tag $img localhost:5000/$(image_name $profile)
    podman push --tls-verify=false localhost:5000/$(image_name $profile)

    if command -v ldapsearch &> /dev/null; then
      inform "Running image"
      podman run -d --name checkglauth -p $(ldap_port $profile):$(ldap_port $profile) localhost:5000/$(image_name $profile)
        sleep 3
        inform "Testing image"
        checkfailed=0
        if (ldapsearch -LLL -H ldap://localhost:$(ldap_port $profile) -D cn=serviceuser,ou=svcaccts,dc=glauth,dc=com -w mysecret -x -bdc=glauth,dc=com cn=hackers | grep posixAccoun) &> /dev/null; then
            echo "Checked glauth is responding properly to ldapsearch query."
        else
            checkfailed=1
            echo "glauth check did not pass. Aborting."
        fi
        inform "Stopping image"
        podman stop checkglauth && podman rm checkglauth
        if [[ checkfailed -eq 1 ]]; then
            # Note that we are not removing the registry so that
            # we can manually check why we failed.
            exit 1
        fi
    else
        echo "Skipping ldapsearch sanity check. Command not present."
    fi

    inform "Stopping registry"
    podman stop registry && podman rm registry
}

prepare_images() {
    prepare_image standalone
    prepare_image plugins
}

push_profile_to_docker() {
    profile="$1"
    tag="$2"
    REGISTRY_AUTH_FILE=~/.podmanauth
    echo "Pushing image to docker hub"
    podman login
    podman push localhost:5000/$(image_name $profile) docker.io/glauth/$(image_name $profile):$tag
}

push_to_docker() {
    tag="$1"
    push_profile_to_docker standalone $tag
    push_profile_to_docker plugins $tag
}

clear
cat <<EOB
This script is now deprecated.
Please use:

make releasedocker
make testdocker

EOB
exit 0

TAG="$1"

if [[ "$1" != "--force" ]]; then
    tested=0
    found=0

    if command -v lsof &> /dev/null; then
        tested=1
        if lsof -i :5000 &> /dev/null; then
            found=1
        fi
    elif command -v fuser &> /dev/null; then
        tested=1
        if fuser 5000/tcp &> /dev/null; then
            found=1
        fi
    elif command -v netstat &> /dev/null; then
        tested=1
        if (netstat -plnt | grep 5000) &> /dev/null; then
            found=1
        fi
    fi
    if [[ tested -eq 0 ]]; then
        echo "Unable to figure out whether a registry is already running."
        echo "Please install lsof, fuser or netstat, or run with '--force'"
        exit 1
    fi
    if [[ found -eq 1 ]]; then
        echo "Port 5000 is busy. I will not be able to run the local registry. Aborting."
        echo "You can avoid this check by running with '--force'"
        exit 1
    fi
else
    TAG="$2"
fi

if [[ "$TAG" == "" ]]; then
    echo "Please provide a tag for this image."
    exit 1
fi

prepare_images

while true; do
    read -p "Everything seems ok. Push to Docker registry? (y/n) " yn
    case $yn in
        [Yy]* ) push_to_docker $TAG; push_to_docker latest; break;;
        [Nn]* ) exit;;
    esac
done
