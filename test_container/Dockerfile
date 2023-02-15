FROM quay.io/kuryr/alpine:3.12

ADD rootfs.tar.xz /
RUN apk update && apk add iputils
RUN adduser -S kuryr --uid 100

USER 100
WORKDIR /home/kuryr

EXPOSE 8080
CMD ["/usr/bin/helloserver"]
