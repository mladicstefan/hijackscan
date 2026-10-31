#!/bin/sh
# victim / attacker host: authoritative NSD for victim.rs and the HTTP-01 responder.
nsd -d -c /lab/nsd.conf &
exec python3 /usr/local/bin/web.py --config /lab/web.json --port 80
