# wgmesh

Custom WireGuard mesh coordinator (Project Black Mesh). Slice S-A only:
coordinator skeleton.

## What S-A builds

- SQLite schema: `nodes` table and `preauth_keys` table (hashes only).
- `POST /preauth`: coordinator-local CLI only. `wgmesh admin create-key`
  mints a single-use pre-auth key, returned once, stored as a SHA-256 hash.
  Non-loopback requests are rejected.
- `POST /register`: Bearer pre-auth key, body `{"name", "pubkey"}`.
  Allocates (or reclaims) a stable mesh IP from `10.66.0.0/24` and returns
  `{"mesh_ip", "peers[]"}`. The key is consumed on success only.
- IP allocator for `10.66.0.0/24`: lowest free address from `.3` upward.
  Excluded: `.0` (network), `.1` (reserved for the R320 per the approved
  addressing gate), `.2` (reserved for x390 per the approved addressing
  gate), `.255` (broadcast). Re-registering the same pubkey
  returns its existing IP. A name may belong to only one pubkey.

## What S-A does NOT build

No node agent, no tunnel, no WireGuard config, no other endpoints
(`/peers`, `/heartbeat`, `/revoke` are later slices), no UI. The coordinator
service binds loopback by default and is never publicly exposed; the repo
being public does not make the service public.

## Keys discipline (hard rule)

Test with FAKE public keys only. No real private keys anywhere. Pre-auth
keys are shown once at creation, stored hashed, and never committed to git,
never written to logs, and never pasted into chat or log files.

## Build and run

```bash
go build -o wgmesh .
./wgmesh serve -listen 127.0.0.1:8080 -db wgmesh.db
```

Mint a key (on the coordinator host) and register a node:

```bash
KEY=$(./wgmesh admin create-key)
curl -s -X POST http://127.0.0.1:8080/register \
  -H "Authorization: Bearer $KEY" \
  -d '{"name": "x390", "pubkey": "FAKEPUBKEY-EXAMPLE-0001"}'
```

## S-A exit check

Two fake pubkeys register via curl and get stable IPs; re-registering the
same pubkey returns the same IP. Proof output is recorded in the sprint
results log. Two failed attempts at the exit check means stop, write it up,
re-plan — do not keep pushing.
