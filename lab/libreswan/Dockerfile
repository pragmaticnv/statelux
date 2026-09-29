FROM alpine:3.18

RUN apk update && apk add --no-cache \
    libreswan \
    iproute2 \
    iptables \
    tcpdump \
    bash \
    curl

RUN mkdir -p /etc/ipsec.d /captures /var/run/pluto

COPY ipsec.conf /etc/ipsec.conf

EXPOSE 500/udp 4500/udp

CMD ["/usr/libexec/ipsec/pluto", "--nofork", "--config", "/etc/ipsec.conf"]
