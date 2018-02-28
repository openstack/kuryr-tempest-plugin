======================================
Kuryr Testing container infrastructure
======================================

This directory is the official source for building Docker hub's kuryr/demo
images.

The build consists on two parts:

Builder container
-----------------

The builder container is based on the musl compiled Alpine distribution. In the
process of building the image, it downloads and compiles:

* busybox
* musl
* curl and its dependencies

It also includes golang so that we can use it in our test web server:

* server.go

Everything that is to be included in the kuryr/demo image is put in::

    /usr/src/busybox/rootfs

The reason for this is that this build is based on Docker's busybox build
system and the rootfs won't have any library, so all you want to add must be
statically compiled there.

kuryr/demo container
--------------------

This is the actual container used in the tests. It includes:

* Busybox: It gives us a very lightweight userspace that provides things like
  the ip command, vi, etc.
* curl: Useful for testing HTTP/HTTPS connectivity to the API and other
  services.
* helloserver: An HTTP server that binds to 8080 and prints out a message
  that includes the hostname, so it can be used to see which pod replies to a
  service request.

When and how to build
---------------------

builder container + kuryr/demo
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You should only need to build the whole set if you want to change the library
app version of something in kuryr/demo or add another tool like bind9 dig.

The way to do this is::

    sudo ./mkrootfs.sh


kuryr/demo
~~~~~~~~~~

Everytime you want to run the tests, you should build the kuryr/demo container
locally to avoid pulls from dockerhub to make sure you run the latest
authoritative version.

Note that the kuryr-tempest-plugin devstack will build it for you.
