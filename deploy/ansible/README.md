# Ansible deployment

`playbook.yml` lays SimpleSIEM down on every host in the `simplesiem_agents` group and joins them to a server you've already stood up. It assumes the server is reachable from the agents and you have the current enrolment PSK.

## Pre-flight

1. Stand up the server (manually, or via a separate playbook):
   ```bash
   sudo simplesiem install --mode server
   ```
1. Pull the enrolment PSK off the server:
   ```bash
   ssh siem.example.com 'sudo simplesiem certs psk show'
   ```
1. Build the agent binary for the target architecture (or download the release artifact) and put it at `dist/simplesiem-linux-x86_64`. The playbook resolves the path with `ansible_system` + `ansible_architecture`, so name your binaries to match (e.g. `simplesiem-linux-aarch64` for ARM64 hosts).

## Run

```bash
ansible-playbook -i inventory.example.ini deploy/ansible/playbook.yml \
    -e simplesiem_server_url=https://siem.example.com:9443 \
    -e simplesiem_enrol_key=PASTE-PSK-HERE
```

## Re-enrol after PSK rotation

```bash
ansible-playbook -i inventory.example.ini deploy/ansible/playbook.yml \
    -e simplesiem_server_url=https://siem.example.com:9443 \
    -e simplesiem_enrol_key=NEW-PSK \
    -e simplesiem_force_reenrol=true
```

The play short-circuits hosts that already carry an install marker (`/var/lib/simplesiem/.installed`); pass `simplesiem_force_reenrol=true` to re-run install on top of the existing tree (the install command handles the upgrade path).

## Realms

To group hosts into a SimpleSIEM realm (multi-server federation), pass `simplesiem_realm=<realm-name>` either as a play extra-var or in `simplesiem_agents:vars`.
