#!/bin/bash

prepare_image() {
    img="localhost/glauth"

    podman build --security-opt seccomp=scripts/docker/fastat-workaround.json -f Dockerfile -t "$img"

    podman run -d --name registry -p 5000:5000 -v ./local/registry:/var/lib/registry --restart=unless-stopped registry:2

    podman tag localhost/glauth localhost:5000/glauth
    podman push --tls-verify=false localhost:5000/glauth

    if command -v ldapsearch &> /dev/null; then
        podman run -d --name checkglauth -p 3893:3893 localhost:5000/glauth
        sleep 3
        checkfailed=0
        if (ldapsearch -LLL -H ldap://localhost:3893 -D cn=serviceuser,ou=svcaccts,dc=glauth,dc=com -w mysecret -x -bdc=glauth,dc=com cn=hackers | grep posixAccoun) &> /dev/null; then
            echo "Checked glauth is responding properly to ldapsearch query."
        else
            checkfailed=1
            echo "glauth check did not pass. Aborting."
        fi
        podman stop checkglauth && podman rm checkglauth
        if [[ checkfailed -eq 1 ]]; then
            exit 1
        fi
    else
        echo "Skipping ldapsearch sanity check. Command not present."
    fi

    podman stop registry && podman rm registry
}

push_to_docker() {
    REGISTRY_AUTH_FILE=~/.podmanauth
    echo "Pushing image to docker hub"
    podman login
    podman push localhost:5000/glauth docker.io/glauth/glauth:$1
}

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

prepare_image

while true; do
    read -p "Everything seems ok. Push do Docker registry? (y/n) " yn
    case $yn in
        [Yy]* ) push_to_docker $TAG; break;;
        [Nn]* ) exit;;
    esac
done
