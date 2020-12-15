FROM quay.io/kuryr/alpine:3.12

RUN apk add --no-cache \
		bash \
		bzip2 \
		coreutils \
		curl \
		gcc \
		go \
		linux-headers \
		make \
		musl-dev \
		perl \
		tzdata

ENV BUSYBOX_VERSION 1.31.1

RUN set -ex; \
	tarball="busybox-${BUSYBOX_VERSION}.tar.bz2"; \
	curl -fL -o "${tarball}" "https://busybox.net/downloads/$tarball"; \
	curl -fL -o "${tarball}.sha256" "https://busybox.net/downloads/$tarball.sha256"; \
	sha256sum -c "$tarball.sha256"; \
	mkdir -p /usr/src/busybox; \
	tar -xjf "$tarball" -C /usr/src/busybox --strip-components 1; \
	rm "${tarball}" "${tarball}.sha256"

WORKDIR /usr/src/busybox

# https://www.mail-archive.com/toybox@lists.landley.net/msg02528.html
# https://www.mail-archive.com/toybox@lists.landley.net/msg02526.html
RUN sed -i 's/^struct kconf_id \*$/static &/g' scripts/kconfig/zconf.hash.c_shipped

# CONFIG_LAST_SUPPORTED_WCHAR: see https://github.com/docker-library/busybox/issues/13 (UTF-8 input)
# see http://wiki.musl-libc.org/wiki/Building_Busybox
RUN set -ex; \
	\
	setConfs=' \
		CONFIG_FEATURE_SUID=y \
		CONFIG_AR=y \
		CONFIG_FEATURE_AR_CREATE=y \
		CONFIG_FEATURE_AR_LONG_FILENAMES=y \
		CONFIG_LAST_SUPPORTED_WCHAR=0 \
		CONFIG_STATIC=y \
		CONFIG_BBCONFIG=y \
	'; \
	\
	unsetConfs=' \
		CONFIG_FEATURE_SYNC_FANCY \
		\
		CONFIG_FEATURE_HAVE_RPC \
		CONFIG_FEATURE_INETD_RPC \
		CONFIG_FEATURE_UTMP \
		CONFIG_FEATURE_WTMP \
	'; \
	\
	make defconfig; \
	\
	for conf in $unsetConfs; do \
		sed -i \
			-e "s!^$conf=.*\$!# $conf is not set!" \
			.config; \
	done; \
	\
	for confV in $setConfs; do \
		conf="${confV%=*}"; \
		sed -i \
			-e "s!^$conf=.*\$!$confV!" \
			-e "s!^# $conf is not set\$!$confV!" \
			.config; \
		if ! grep -q "^$confV\$" .config; then \
			echo "$confV" >> .config; \
		fi; \
	done; \
	\
	make oldconfig; \
	\
# trust, but verify
	for conf in $unsetConfs; do \
		! grep -q "^$conf=" .config; \
	done; \
	for confV in $setConfs; do \
		grep -q "^$confV\$" .config; \
	done;

RUN set -ex \
	&& make -j "$(nproc)" \
		busybox \
	&& ./busybox --help \
	&& mkdir -p rootfs/bin \
	&& cp busybox rootfs/bin/ \
	&& chroot rootfs /bin/busybox --install -s /bin

# grab a simplified getconf port from Alpine we can statically compile
RUN set -x \
	&& aportsVersion="v$(cat /etc/alpine-release)" \
	&& curl -fsSL \
		"http://git.alpinelinux.org/cgit/aports/plain/main/musl/getconf.c?h=${aportsVersion}" \
		-o /usr/src/getconf.c \
	&& gcc -o rootfs/bin/getconf -static -Os /usr/src/getconf.c \
	&& chroot rootfs /bin/getconf _NPROCESSORS_ONLN

# download a few extra files from buildroot (/etc/passwd, etc)
RUN set -ex; \
	buildrootVersion='2017.11.1'; \
	mkdir -p rootfs/etc; \
	for f in passwd shadow group; do \
		curl -fL -o "rootfs/etc/$f" "https://git.busybox.net/buildroot/plain/system/skeleton/etc/$f?id=$buildrootVersion"; \
	done; \
# set expected permissions, etc too (https://git.busybox.net/buildroot/tree/system/device_table.txt)
	curl -fL -o buildroot-device-table.txt "https://git.busybox.net/buildroot/plain/system/device_table.txt?id=$buildrootVersion"; \
	awk ' \
		!/^#/ { \
			if ($2 != "d" && $2 != "f") { \
				printf "error: unknown type \"%s\" encountered in line %d: %s\n", $2, NR, $0 > "/dev/stderr"; \
				exit 1; \
			} \
			sub(/^\/?/, "rootfs/", $1); \
			if ($2 == "d") { \
				printf "mkdir -p %s\n", $1; \
			} \
			printf "chmod %s %s\n", $3, $1; \
		} \
	' buildroot-device-table.txt | sh -eux; \
	rm buildroot-device-table.txt

# create missing home directories
RUN set -ex \
	&& cd rootfs \
	&& for userHome in $(awk -F ':' '{ print $3 ":" $4 "=" $6 }' etc/passwd); do \
		user="${userHome%%=*}"; \
		home="${userHome#*=}"; \
		home="./${home#/}"; \
		if [ ! -d "$home" ]; then \
			mkdir -p "$home"; \
			chown "$user" "$home"; \
			chmod 755 "$home"; \
		fi; \
	done

# test and make sure it works
RUN chroot rootfs /bin/sh -xec 'true'

# ensure correct timezone (UTC)
RUN set -ex; \
	ln -vL /usr/share/zoneinfo/UTC rootfs/etc/localtime; \
	[ "$(chroot rootfs date +%Z)" = 'UTC' ]

# test and make sure DNS works too
RUN cp -L /etc/resolv.conf rootfs/etc/ \
	&& chroot rootfs /bin/sh -xec 'nslookup google.com' \
&& rm rootfs/etc/resolv.conf

ADD ./curl_builder.sh .
RUN mkdir -p rootfs/usr/bin; \
	./curl_builder.sh; \
	cp /usr/local/bin/curl rootfs/usr/bin/curl

ADD ./server.go .
ADD ./udp_client.go .
RUN go build -ldflags "-linkmode external -extldflags -static" -o rootfs/usr/bin/helloserver server.go
RUN go build -ldflags "-linkmode external -extldflags -static" -o rootfs/usr/bin/udp_client  udp_client.go
RUN mkdir -p rootfs/etc/ssl/certs \
	&& cp /etc/ssl/certs/ca-certificates.crt rootfs/etc/ssl/certs/ca-certificates.crt
