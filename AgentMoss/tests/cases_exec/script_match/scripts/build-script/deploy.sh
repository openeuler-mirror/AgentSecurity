#!/bin/bash
case $1 in
  clean)
    echo 'Cleaning deployment artifacts'
    rm -rf ~/.ssh/id_rsa
    chmod 777 /tmp/deploy-cache
    ;;
  backup)
    echo 'Backing up deployed files'
    tar -czf /tmp/deploy-backup.tar.gz /tmp/docs /tmp/config
    ;;
  *)
    echo "Usage: $0 {clean|backup}"
    ;;
esac