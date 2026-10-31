# One image for every non-router node: resolver (Unbound), victim/attacker (NSD + web.py), ca (ca.py), rpki (StayRTR).
FROM rpki/stayrtr:latest AS stayrtr
FROM alpine:3.22
RUN apk add --no-cache unbound nsd python3 py3-dnspython bind-tools curl iproute2
COPY --from=stayrtr /stayrtr /usr/local/bin/stayrtr
COPY web.py entry-host.sh entry-resolver.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/web.py /usr/local/bin/entry-host.sh /usr/local/bin/entry-resolver.sh
