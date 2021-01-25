FROM quay.io/kuryr/alpine:3.12

RUN apk add --no-cache \
                bash \
                gcc \
                g++ \
                libstdc++ \
                linux-headers \
                lksctp-tools \
                lksctp-tools-dev \
                openssh-client \
                net-tools \
                python3 \
                py3-pip \
                python3-dev

ENV BUSYBOX_VERSION 1.31.1
RUN adduser -S kuryr
USER kuryr

WORKDIR /home/kuryr
COPY kuryr_sctp_demo/sctp_server.py /sctp_server.py
COPY kuryr_sctp_demo/sctp_client.py /home/kuryr/sctp_client.py

RUN pip3 --no-cache-dir install -U pip \
        && python3 -m pip install pysctp

EXPOSE 9090
ENTRYPOINT ["python3", "/sctp_server.py"]
