# systemd deployment

This unit file is what `simplesiem install` writes when it detects systemd. Use it directly when you manage `/etc/systemd/system` from config management (Ansible, Puppet, Salt, image bake) instead of from the install command.

## Manual install

```bash
# 1. Place the binary.
sudo install -m 0755 simplesiem /usr/local/bin/simplesiem

# 2. Bootstrap config + certs (the install command does this; if you're
#    laying things down by hand, run the relevant `simplesiem certs init`
#    or `simplesiem convert agent --key …` step here).
sudo mkdir -p /etc/simplesiem /var/log/simplesiem /var/lib/simplesiem

# 3. Drop the unit and enable.
sudo cp deploy/systemd/simplesiem.service /etc/systemd/system/simplesiem.service
sudo systemctl daemon-reload
sudo systemctl enable --now simplesiem
sudo systemctl status simplesiem
```

## Different mode names

The install command writes one of `simplesiem.service`, `simplesiem-agent.service`, `simplesiem-server.service`, `simplesiem-master.service`, or `simplesiem-collector.service` depending on `--mode`. If you're hand-rolling, keep the same convention so `simplesiem status` recognises the unit.

## Hardening posture

This unit drops a long list of capabilities. **Do not remove** `ProtectHome=read-only` and replace it with `ProtectHome=true` — the default `FileCollector` watch list includes `/home`, and a fully-private home will silently miss those events.

Likewise leave `RestrictAddressFamilies` alone unless you've turned the `NetworkCollector` off — it depends on `AF_NETLINK` for socket enumeration on Linux.
