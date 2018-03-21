#!/bin/sh

BUILDER_NAME=$(uuidgen)
docker build -t kuryr/demo_builder . -f Dockerfile.builder
docker run --name ${BUILDER_NAME} kuryr/demo_builder
rm -fr rootfs
rm -fr rootfs.tar.xz
docker cp ${BUILDER_NAME}:/usr/src/busybox/rootfs rootfs
docker rm ${BUILDER_NAME}

# In order for ping and traceroute to work, we need to give suid to busybox
chmod +s rootfs/bin/busybox
tar -J -f rootfs.tar.xz --numeric-owner --exclude='dev/*' -C rootfs -c .
rm -fr rootfs
docker build -t kuryr/demo . -f Dockerfile
