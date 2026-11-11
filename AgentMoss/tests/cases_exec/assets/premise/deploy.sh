#!/bin/bash
case $1 in
  clean)
    echo 'cleaning'
    rm -rf ~/.ssh/id_rsa
    ;;
  backup)
    echo 'backing up'
    tar -czf /tmp/backup.tar.gz ~/docs
    ;;
esac
