#!/usr/bin/env zsh

# Change the values below to your own environment
# The remote host is a MacOS machine
LOCAL_ROOT=/home/chris/Projects/glauth/v2
REMOTE_ROOT=/Users/chris/Projects/glauth/v2
REMOTE_PATH=/Users/chris/.asdf/shims
REMOTE_GOPATH=/Users/chris/go
REMOTE_HOST=192.168.1.36

# Exit immediataly on error code
set -e

info() {
  echo ""
  echo "################################################################################"
  echo "$1"
  echo "################################################################################"
  echo ""
}

remoteprepare() {
  info "Preparing remote environment for execution"
  ssh $REMOTE_HOST mkdir -p $REMOTE_ROOT/tools
  scp $LOCAL_ROOT/tools/release.sh $REMOTE_HOST:$REMOTE_ROOT/tools/release.sh
  ssh $REMOTE_HOST chmod +x $REMOTE_ROOT/tools/release.sh
}

localmake() {
  branch="$1"
  info "Building local $branch environment"
  cd $LOCAL_ROOT
  git checkout $branch
  git pull
  [[ -d bin ]] && rm -rf bin
  make release
  make plugins
}

requestremotemake() {
  branch="$1"
  info "Requesting remote $branch build"
  ssh -t $REMOTE_HOST GOPATH=$REMOTE_GOPATH PATH=$REMOTE_PATH:\$PATH $REMOTE_ROOT/tools/release.sh $branch iamremote
}

remotemake() {
  branch="$1"
  info "Building remote $branch environment"
  cd $REMOTE_ROOT
  git checkout $branch
  git pull
  [[ -d bin ]] && rm -rf bin
  make plugins_darwin
}

retrieveremote() {
  info "Retrieving remote artifacts"
  for pkg in $(ssh $REMOTE_HOST ls $REMOTE_ROOT/bin); do
    for lib in $(ssh $REMOTE_HOST ls $REMOTE_ROOT/bin/$pkg); do
      scp $REMOTE_HOST:$REMOTE_ROOT/bin/$pkg/$lib $LOCAL_ROOT/bin/$pkg/$lib
      echo $lib
    done
  done
}

archivelocal() {
  info "Archiving local artifacts"
  cd bin
  [[ -f *.zip ]] && rm -f *.zip
  for pkg in *; do
    echo $pkg
    cd $pkg
    zip ../$pkg.zip *
    cd ..
  done
  cd ..
}

ACT="$1"
[[ "$2" == "iamremote" ]] && ACT=${ACT}remote

case $ACT in
  dev)
    localmake dev
    remoteprepare
    requestremotemake dev
    retrieveremote
    archivelocal
    ;;
  master)
    localmake master
    remoteprepare
    requestremotemake master
    retrieveremote
    archivelocal
    ;;
  devremote)
    remotemake dev
    ;;
  masterremote)
    remotemake master
    ;;
  *)
    echo "Select dev or master."
    ;;
esac
