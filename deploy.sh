#!/usr/bin/env bash

cd /home/b/Documents/frame-admin-api || exit
docker run --rm -v "$(pwd)":/app rust_cross_compile:aarch64_1.88.0-bookworm
ssh p4 "cd /home/b/docker/frame && docker-compose stop admin-api"
scp "$(pwd)"/target/aarch64-unknown-linux-gnu/release/admin_api p4:/home/b/docker/frame/services/admin-api/app/
scp -r "$(pwd)"/public p4:/home/b/docker/frame/services/admin-api/app/
scp -r "$(pwd)"/templates p4:/home/b/docker/frame/services/admin-api/app/
ssh p4 "mkdir -p /home/b/docker/frame/services/admin-api/app/secrets"
ssh p4 "cd /home/b/docker/frame && docker-compose build admin-api"
ssh p4 "cd /home/b/docker/frame && docker-compose up -d admin-api"
