# Local Development with Podman (rootless, no subuid)

This guide covers running the full Precogly stack locally with
`podman-compose` on a Linux host where the user account has **no
`subuid`/`subgid` delegation** (common on GSA-managed laptops where a domain
account uid is outside `/etc/subuid`). Standard rootless Podman assumes each
user has a range of ~65k subordinate UIDs; without them, image extraction and
container startup both fail. The steps below make Podman usable in that
environment without needing `sudo`.

!!! note "Docker users"
    If you have Docker Desktop or Docker Engine with normal permissions, use
    the [Installation](installation.md) guide instead — none of the
    workarounds here are needed.

## Symptoms of missing subuid/subgid delegation

Running the compose stack fails with either of:

```text
processing tar file(potentially insufficient UIDs or GIDs available in user
namespace (requested 0:42 for /etc/shadow): Check /etc/subuid and /etc/subgid
if configured locally and run "podman system migrate": lchown /etc/shadow:
invalid argument): exit status 1
```

```text
chown: /var/lib/postgresql/data: Invalid argument
```

```text
Error: OCI runtime error: crun: write to
`/proc/sys/net/ipv4/ping_group_range`: Invalid argument
```

All three come from the same root cause: your rootless user namespace only
has a single UID mapping (`host_uid → container 0`), so any file operation
that references a container uid ≠ 0 fails.

## One-time host configuration

Create `~/.config/containers/storage.conf` to let image extraction skip
`chown` calls that reference container-only uids:

```toml
[storage]
driver = "overlay"

[storage.options.overlay]
# Without subuid delegation, rootless podman only has a single UID mapping.
# Some image layers (e.g. postgres) chown /etc/shadow to gid 42, which fails.
# Skipping the chown lets the image extract; the file ends up owned by
# container-root, which the image runs as anyway.
ignore_chown_errors = "true"
mountopt = "nodev,metacopy=on"
```

Create `~/.config/containers/containers.conf` to disable the sysctl
Podman/CRUN try to set at container start, which is rejected by the host
kernel from an unprivileged user namespace:

```toml
[containers]
default_sysctls = []
```

Apply the new storage settings (this wipes any existing rootless images and
containers):

```bash
podman system reset --force
```

## Compose overlay

The canonical stack lives in `docker-compose.yml` and is shared with Docker.
For rootless Podman without subuid delegation, layer the small
[podman-compose.override.yml](https://github.com/precogly/precogly/blob/main/podman-compose.override.yml)
overlay on top of it. The overlay adds only:

- **`db.userns_mode: "keep-id:uid=70,gid=70"`** — maps the container's
  postgres user (uid 70) to the host user. Without this, the postgres
  entrypoint's `chown` on `/var/lib/postgresql/data` fails inside the
  restricted user namespace.
- **`db.image: docker.io/library/postgres:16-alpine`** — the fully qualified
  reference so rootless Podman does not prompt for a registry.

Everything else (build targets, mounts, ports, env) comes from
`docker-compose.yml` unchanged.

## Bringing up the stack

```bash
cd precogly
podman-compose -f docker-compose.yml -f podman-compose.override.yml up -d
```

Verify:

```bash
podman ps --format 'table {{.Names}}\t{{.Status}}'
# NAMES              STATUS
# precogly-postgres  Up X seconds (healthy)
# precogly-backend   Up X seconds
# precogly-frontend  Up X seconds

curl -s http://localhost:8000/api/health/
# {"status":"healthy"}

curl -s -o /dev/null -w "%{http_code}\n" http://localhost:5173/
# 200
```

Open `http://localhost:5173` in a browser and log in with the seeded demo
credentials from the [Installation](installation.md) guide.

## Tearing down

```bash
podman-compose -f docker-compose.yml -f podman-compose.override.yml down
podman volume rm precogly_postgres_data     # optional: wipe database
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `insufficient UIDs or GIDs available` during pull | Add `ignore_chown_errors = "true"` to `storage.conf`, then `podman system reset --force`. |
| `chown: /var/lib/postgresql/data: Invalid argument` | Ensure the compose service has `userns_mode: "keep-id:uid=70,gid=70"`. |
| `write to /proc/sys/net/ipv4/ping_group_range: Invalid argument` | Add `default_sysctls = []` under `[containers]` in `containers.conf`. |
| Container starts then exits with no logs | Usually the postgres `chown` failure — check `podman inspect <name> --format '{{.State.ExitCode}}'` and re-verify `userns_mode`. |
| Warnings `Additional gid=N is not present in the user namespace` | Harmless; they're the postgres entrypoint's supplementary groups the single-UID mapping cannot represent. |

## When to switch to full Podman rootless

If your host administrator adds an entry to `/etc/subuid` and
`/etc/subgid` for your account (e.g. `youruser:100000:65536`), you can
remove `ignore_chown_errors`, `default_sysctls`, and drop the overlay,
then `podman system migrate` to pick up the new range. `docker-compose.yml`
works on its own either way.
