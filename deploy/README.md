# Deployment recipes - NOT TESTED

Three reference deployments, each in its own directory:

| Recipe | When to use |
|---|---|
| [`systemd/`](systemd/) | Single-host or small fleet on Linux with systemd. The recipe is the same unit `simplesiem install` writes; lift it directly when your config-management tool owns `/etc/systemd/system`. |
| [`ansible/`](ansible/) | Rolling tens-to-hundreds of agents into an existing server. Idempotent re-runs; supports realm assignment and PSK rotation re-enrolment. |
| [`k8s/`](k8s/) | Per-node node-level monitoring on Kubernetes. **Privileged DaemonSet** — uses host PID + host network namespaces because container-isolated agents see only their own container, not the node. |

For Mac and Windows, the `simplesiem install` command writes a launchd plist and a Windows service registration respectively. There is no "hand-rolled recipe" equivalent for those platforms — the install command is the recipe.
