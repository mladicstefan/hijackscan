---
name: docker
description: Docker specifics for the hijackscan lab - the pinned images (FRR, StayRTR, Unbound, Alpine), how containerlab uses Docker, running FRR with the rpki module, bridge networks and disabling egress, exec/logs for debugging, and keeping images reproducible. Use when choosing or pinning an image, writing an FRR daemons file, or debugging a container that won't start or can reach the Internet.
---

# Docker for the hijackscan lab

containerlab runs each node as a Docker container, so Docker is the runtime underneath
the [containerlab](../containerlab) skill. This skill covers the image and container
details that lab configs depend on. Pinned facts live in `lab-tooling-facts` in memory.

## Pinned images (verified 2026-10-31)

| Node | Image | Notes |
|---|---|---|
| FRR routers | `quay.io/frrouting/frr:v10.7.1` | Docker Hub `frrouting/frr` is stale at 8.x - do not use it |
| RPKI cache | `rpki/stayrtr` | serves ROAs from one local `rpki.json`; no ASPA |
| Resolver | build from `alpine` + `unbound`, or a pinned `unbound` image | needs a local root trust anchor |
| CA / feed | `python:3.12-slim` (or match `pyproject.toml`) | small purpose-built services |

Always pin a tag or digest. A moving `:latest` makes a run unrepeatable, which the
reproducibility review will flag.

## Running FRR with RPKI

FRR needs the `rpki` module enabled or `vtysh` has no rpki commands. Bind a `daemons`
file that turns on `bgpd` with `-M rpki`:

```
# lab/routing/<node>/frr/daemons  (bind to /etc/frr)
bgpd=yes
zebra=yes
bgpd_options="   -A 127.0.0.1 -M rpki"
```

Bind `frr.conf` alongside it with the `rpki cache tcp <stayrtr-ip> 3323 preference 1`
block and the `match rpki invalid` route-map. Check it after deploy:

```bash
docker exec clab-hijacklab-transit-a vtysh -c "show rpki cache-connection"
docker exec clab-hijacklab-transit-a vtysh -c "show rpki prefix-table"
```

## Networking and egress

containerlab creates one Docker bridge network for management (`eth0` on each node) and
veth pairs for the data links. The management bridge **NATs to the Internet by default**;
the lab must disable that (see the containerlab skill's `mgmt.driver-opts`
`enable_ip_masquerade: "false"`). To confirm a container cannot egress:

```bash
docker exec clab-hijacklab-origin ip route          # must show no default via the mgmt gw
docker network inspect clab-hijacklab-mgmt           # check the bridge options
```

Data-plane addressing goes on `eth1`+ via the node's `exec` (containerlab), all inside
RFC 5737 space.

## Debugging

```bash
docker ps --filter name=clab-hijacklab           # which nodes are up
docker logs clab-hijacklab-rpki                   # StayRTR / CA startup errors
docker exec -it clab-hijacklab-ca sh              # shell into a node
docker inspect -f '{{.State.Health.Status}}' <c>  # if the image has a healthcheck
```

A container that exits immediately is usually a bad bind path or a config the daemon
rejects - check `docker logs` first, then the bound file on the host.

## Reproducibility

- Pin every image; record digests if the result depends on them.
- Keep images local once pulled so a rebuild needs no registry (offline containment).
- Do not add `--privileged` or host networking to a node unless a kind demands it; it
  widens the blast radius and breaks containment.
