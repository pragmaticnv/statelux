FROM alpine:3.18

RUN apk update && apk add --no-cache \
    strongswan \
    iproute2 \
    iptables \
    tcpdump \
    tshark \
    bash \
    curl

RUN mkdir -p /etc/swanctl/conf.d /captures /scripts

COPY swanctl.conf /etc/swanctl/swanctl.conf

EXPOSE 500/udp 4500/udp

CMD ["/usr/sbin/charon-systemd"]
