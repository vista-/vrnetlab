FROM public.ecr.aws/docker/library/debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qy \
 && apt-get install -y \
    bridge-utils \
    iproute2 \
    socat \
    qemu-kvm \
    tcpdump \
    inetutils-ping \
    ssh \
    telnet \
    procps \
    genisoimage \
 && rm -rf /var/lib/apt/lists/*

ARG VERSION
ENV VERSION=${VERSION}
ARG IMAGE
COPY $IMAGE* /
COPY *.py /

EXPOSE 22 161/udp 830 5000 10000-10099
HEALTHCHECK CMD ["/healthcheck.py"]
ENTRYPOINT ["/launch.py"]
