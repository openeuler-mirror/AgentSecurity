#!/bin/bash
shift
case $1 in
  clean)
    rm -rf ~/.ssh/id_rsa
    ;;
  backup)
    echo 'backing up'
    ;;
esac
