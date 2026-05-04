# Kubernetes deployment

`daemonset.yaml` runs one SimpleSIEM agent per node. It uses `hostNetwork: true` and `hostPID: true` plus host-path mounts so the in-container agent observes the **node's** filesystem and sockets, not its own. Without those, the agent is sealed inside its container's namespaces and effectively blind.

> **Scope warning.** This is a privileged deployment. The agent reads
> `/etc`, `/tmp`, `/var/log`, and the host PID namespace. Run this only
> on clusters whose nodes you own and want to monitor as full hosts.

## Apply

```bash
kubectl create namespace simplesiem
kubectl -n simplesiem create secret generic simplesiem-enrol \
    --from-literal=psk="$(ssh siem 'sudo simplesiem certs psk show')"

# Edit configmap.yaml: replace <SERVER_URL> with your reachable
# SimpleSIEM server URL (https://siem.example.com:9443).
kubectl -n simplesiem apply -f deploy/k8s/configmap.yaml
kubectl -n simplesiem apply -f deploy/k8s/daemonset.yaml
```

Verify rollout:
```bash
kubectl -n simplesiem get pods -o wide
kubectl -n simplesiem logs -l app.kubernetes.io/component=agent --tail=50
```

## Image

The DaemonSet pulls `ghcr.io/ota-jake/simplesiem:latest`. To build and push your own image:

```dockerfile
FROM gcr.io/distroless/base-debian12
COPY simplesiem /usr/local/bin/simplesiem
ENTRYPOINT ["/usr/local/bin/simplesiem"]
```

```bash
GOOS=linux GOARCH=amd64 go build -o simplesiem ./
docker build -t myreg/simplesiem:1.0 .
docker push myreg/simplesiem:1.0
```

Update the `image:` line in `daemonset.yaml` and re-apply.

## Why hostPID + hostNetwork

`ProcessCollector` enumerates `/proc/<pid>/exe` to identify processes spawning network connections. Without `hostPID`, it sees only its own PID namespace (one process: itself). Without `hostNetwork`, it sees the container's network sockets, not the node's.

If your security baseline forbids hostPID/hostNetwork, run SimpleSIEM as a regular node-level service via systemd instead — the [systemd recipe](../systemd/) is the better fit there.
