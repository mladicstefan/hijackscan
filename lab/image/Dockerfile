# One image for every non-router node: resolver (Unbound), victim/attacker (NSD + web.py), ca (ca.py), rpki (StayRTR).
# Both bases are pinned by digest (docker image inspect, 2026-10-31) so the image rebuilds the same.
FROM rpki/stayrtr@sha256:b2d5a73be582fffcebbb3154ffaaea0329a1c3f93d079d5a34c6d374b66b9d18 AS stayrtr
# 0.6.4
FROM alpine:3.22@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f
RUN apk add --no-cache unbound nsd python3 py3-dnspython bind-tools curl iproute2
COPY --from=stayrtr /stayrtr /usr/local/bin/stayrtr
COPY web.py entry-host.sh entry-resolver.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/web.py /usr/local/bin/entry-host.sh /usr/local/bin/entry-resolver.sh
