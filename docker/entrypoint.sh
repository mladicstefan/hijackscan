#!/bin/sh
# Start of the demo container: load the demo runs once, then serve the page and the API.
# MongoDB is already healthy here (docker-compose.yml: depends_on ... service_healthy).
set -e

# --skip-existing: after a restart the runs are already in the database volume, so nothing is loaded twice.
hijackscan --data-dir /app/data/demo load data/samples/dev100.txt --name ".rs top 100" --skip-existing
hijackscan --data-dir /app/data/demo load data/samples/ee100.txt --name ".ee sample 100" --skip-existing

echo
echo "  hijackscan is ready: open http://127.0.0.1:8000 in your browser  (API docs: /docs, stop: Ctrl+C)"
echo

# 0.0.0.0 inside the container; docker-compose.yml publishes it on 127.0.0.1 of the host only.
exec hijackscan serve --host 0.0.0.0 --port 8000
