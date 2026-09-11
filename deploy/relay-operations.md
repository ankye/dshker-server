# Relay operations notes (live deployment 2026-09-12)

Field notes for the public TURN relay on a Tencent Cloud box behind a NAT
gateway (public IP 124.223.103.213, internal 10.0.28.3). These are the fixes
that make the relay actually carry datagrams in production; keep them in mind
when touching the relay or re-deploying.

## 1. Allocation error 508 behind the cloud gateway

pion/turn v5 `RelayAddressGeneratorStatic` uses `Address` as the real bind
address. On a cloud box the public IP (relayPublicIP) exists only on the
gateway, never on a local NIC, so `Address: relayPublicIP.String()` makes
every Allocate fail with 508 Insufficient Capacity. The generator must bind
`"0.0.0.0"` and only use `RelayAddress` (the public IP) in the allocation
response. Regression test: `TestServeTURNAdvertisesPublicRelayBehindNAT`.

## 2. Pinned relay port range for the cloud firewall

pion/turn v5 dropped RelayPortMin/Max, so allocations fall on OS ephemeral
ports and the firewall has to admit the whole ephemeral range. `portRangeAllocator`
pins allocations to `relayPortMin..relayPortMax` (config), and the firewall
only admits that range plus the control port. Production: 8000-9999/udp +
8443/udp. Regression test: `TestServeTURNPortRangePinsAllocations`.

## 3. Datagram hairpin needs the public IP on loopback

The relayed socket binds 0.0.0.0 and the server writes the peer datagram to
the peer's *relayed public address* (e.g. 124.223.103.213:8753). With a plain
NAT setup the write goes out eth0 toward the gateway, which has no hairpin
return, and the peer allocation never sees the packet. The box must own the
public IP locally so the kernel delivers the datagram on loopback:

    ip addr add 124.223.103.213/32 dev lo

Persisted with systemd oneshot unit `/etc/systemd/system/dshker-lopub.service`.
Created via `systemctl enable --now dshker-lopub.service`.

Debug tip: with the IP on lo, the relayed datagram shows as a single `lo In`
packet of the form `124.223.103.213:PA > 124.223.103.213:PB`.

## 4. systemd hardening vs the relay

`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` makes the service fail to
start with `p2p.operation_failed` (silenced by main.go's code-only error). The
serving unit must NOT set it. See `deploy/dshker-server.service` for the
comment. Keep NoNewPrivileges/ProtectSystem/ProtectHome/ReadWritePaths.

## 5. Relay debug logging

Set `DSHKER_TURN_DEBUG=1` to get pion debug logs on stderr (allocation,
permission, relay-socket receive, relaying lines).

## 6. End-to-end verification

`relaycheck` (apps/dsh-launcher/networking/cmd/relaycheck, temporary, not
committed) exercises: identity -> turn-credentials -> allocate (A/B) -> pinned
port assertion -> CreatePermission both ways -> A writes to B's relayed
address and B reads, then the reverse. Expect `RELAY-OK both directions over
my.ffkey.com:8443`.

IMPORTANT: the first version of relaycheck used an echo-style check (write on
the same conn the read happens on), which fails forever even though the server
relays correctly. The correct semantics are "write on A, read on B" and
"write on B, read on A".
