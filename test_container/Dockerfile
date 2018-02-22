FROM scratch
ADD rootfs.tar.xz /
RUN adduser -S kuryr

USER kuryr
WORKDIR /home/kuryr

EXPOSE 8080
CMD ["/usr/bin/helloserver"]
