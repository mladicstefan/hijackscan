---
name: containerlab
description: Build and run the offline hijackscan testbed with containerlab - topology YAML schema, the linux kind for FRR/StayRTR/Unbound/CA nodes, links and addressing, deploy/destroy/exec/inspect, and the offline-containment settings (no mgmt egress, RFC 5737, private ASNs). Use when writing a .clab.yml, wiring lab nodes, or debugging why a node has no interfaces or can reach the Internet.
---

# containerlab for the hijackscan lab

containerlab orchestrates Docker containers as network nodes defined in one YAML file.
Every node in this lab is the **`linux` kind** (FRR, StayRTR, Unbound, the CA, the
feed), because they are plain containers we wire by hand. Read
`.claude/prompt.md` for the topology and `lab-tooling-facts` in memory for pinned
versions before writing configs.

## Install (not present on this host)

Install from the upstream script; the Arch AUR package is stale.

```bash
bash -c "$(curl -sL https://get.containerlab.dev)"
containerlab version
```

## Topology file (`lab/topology.clab.yml`)

```yaml
name: hijacklab
topology:
  defaults:
    kind: linux
  kinds:
    linux:
      image: alpine:latest          # per-node images override this
  nodes:
    origin:
      kind: linux
      image: quay.io/frrouting/frr:v10.7.1      # pin a tag, never :latest
      binds:
        - lab/routing/origin/frr:/etc/frr        # host:container[:ro]
      exec:
        - ip addr add 203.0.113.1/24 dev eth1    # eth1+ come from links
    rpki:
      kind: linux
      image: rpki/stayrtr
      binds:
        - lab/routing/rpki.json:/rpki.json:ro
  links:
    - endpoints: ["origin:eth1", "transit-a:eth1"]
    - endpoints: ["transit-a:eth2", "transit-b:eth1"]
```

Inheritance is `node -> group -> kind -> defaults` (most specific wins). `binds` mount
config in; `exec` runs commands after boot (use it to set addresses on `eth1`+);
`startup-config` loads a file but avoid its URL form (needs network). Links create the
`ethN` interfaces in order; `eth0` is always the management interface.

## Offline containment (hard requirement)

Containers reach the Internet through the management bridge by default. Disable it, and
keep every address in RFC 5737 and every ASN in 64512-65534:

```yaml
mgmt:
  network: hijack-mgmt
  ipv4-subnet: 192.0.2.240/28         # RFC 5737 TEST-NET-1
  driver-opts:
    com.docker.network.bridge.enable_ip_masquerade: "false"
  external-access: false              # containerlab touches no host iptables
```

A `lab check` step must still verify no node has a default route off-box, since
containment is the project's non-negotiable rule.

## Run it

```bash
containerlab deploy  -t lab/topology.clab.yml            # bring up (alias: clab dep)
containerlab deploy  -t lab/topology.clab.yml -c         # destroy + redeploy clean
containerlab inspect -t lab/topology.clab.yml            # list nodes, state, mgmt IPs
containerlab exec    -t lab/topology.clab.yml --label clab-node-name=origin \
                     --cmd "vtysh -c 'show rpki prefix-table'"
containerlab destroy -t lab/topology.clab.yml --cleanup  # tear down + remove dirs
```

Containers are named `clab-<labname>-<nodename>` (here `clab-hijacklab-origin`), so plain
`docker exec clab-hijacklab-origin vtysh -c '...'` works too. See the [docker](../docker)
skill for image and network specifics.

## Gotchas

- A node that restarts (on-failure policy) **loses every interface except eth0**. Make
  `exec` idempotent, or redeploy with `-c` rather than restarting one container.
- Relative `binds` resolve against the topology file's directory.
- For FRR, the bind must include a `daemons` file enabling `bgpd` with `-M rpki` (see the
  [docker](../docker) skill), or `vtysh` rpki commands are missing.
- Pin images to a tag or digest; a moving `:latest` breaks reproducibility.
