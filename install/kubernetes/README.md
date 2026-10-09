# Correlic on Kubernetes

Kustomize manifests for the backend planes, the dashboard and a bundled
PostgreSQL, with an optional Neo4j overlay. Images are the
`ghcr.io/fuloxdev/correlic-*:v1.0.1` release; bump them in one place in
`base/kustomization.yaml` (`images:`).

```
install/kubernetes/
├── base/                         PostgreSQL-only profile (the default)
│   ├── namespace.yaml            namespace "correlic" (Pod Security: baseline)
│   ├── configmap.yaml            non-secret settings (URLs, SANs, org name)
│   ├── secret.example.yaml       copy to secret.yaml and fill in
│   ├── certs-pvc.yaml            mTLS material + generated agent.yaml
│   ├── postgres.yaml             PostgreSQL 16 StatefulSet (or use a managed DB)
│   ├── bootstrap-job.yaml        one-shot: certificates, migrations, org, admin, keys
│   ├── backend-api.yaml          cmd/api  :8080 (mTLS)
│   ├── backend-tel.yaml          cmd/telemetry :8081 (mTLS for agents)
│   ├── ui-proxy.yaml             holds the client certificate for the dashboard
│   ├── ui.yaml                   Next.js dashboard :3001
│   ├── ingress.example.yaml      TLS termination in front of the dashboard
│   └── backend-external.example.yaml  LoadBalancer services for agents outside the cluster
└── overlays/graph/               base + Neo4j, NEO4J_* set on both planes
```

What the graph adds, and what runs without it, is listed in
`backend/docs/CORRELATION_ENGINE.md` ("What needs the graph"). In short: the
`ai.data_exfiltration` and `ai.excessive_writes` rules and the Neo4j
process-tree / attack-path timeline need Neo4j; everything else runs on
PostgreSQL alone.

## Apply sequence

1. Secrets. Copy the example, replace every value (`openssl rand -hex 32`
   is fine for all of them), keep the password in `DATABASE_URL` in sync with
   `POSTGRES_PASSWORD`. `secret.yaml` is git-ignored.

   ```sh
   cp install/kubernetes/base/secret.example.yaml install/kubernetes/base/secret.yaml
   $EDITOR install/kubernetes/base/secret.yaml
   ```

2. Configuration. In `base/configmap.yaml` set `FRONTEND_URL` and
   `DASHBOARD_ORIGINS` to the dashboard's public URL (the Ingress host). If
   agents will run on hosts outside the cluster, set `CERT_EXTRA_SANS` to the
   address they will dial and `AGENT_BACKEND_URL` / `AGENT_TELEMETRY_URL`
   accordingly — now, before the first apply: the server certificate is
   generated once and kept.

3. Apply the profile you want:

   ```sh
   kubectl apply -k install/kubernetes/base             # PostgreSQL only
   kubectl apply -k install/kubernetes/overlays/graph   # PostgreSQL + Neo4j
   ```

   `kubectl -n correlic get pods -w` until `postgres-0` is ready, the
   bootstrap Job has completed and the four Deployments are available.
   Switching from the base to the graph overlay later is the same command;
   the overlay only adds Neo4j and the `NEO4J_*` environment.

4. Expose the dashboard. Copy `base/ingress.example.yaml`, set the host and
   the TLS secret, and apply it (or add it to `resources:`). Only the `ui`
   Service goes behind the Ingress; the backend planes stay ClusterIP
   services with mTLS.

## Credentials

The bootstrap Job prints the dashboard login and the agent key once:

```sh
kubectl -n correlic logs job/correlic-bootstrap
```

```
  Log in with the API key:
    <dashboard key>
  or with admin@local.dev / <password>
  Agent key (already in /certs/agent.yaml):
    <agent key>
```

The same values are stored in the certs volume (`dashboard-credentials`,
`agent.yaml`), readable from any pod that mounts it:

```sh
kubectl -n correlic exec deploy/backend-api -- cat /certs/dashboard-credentials
```

## Connecting agents

Agents authenticate with the client certificate and the agent key. From the
certs volume, copy `ca.crt`, `client.crt`, `client.key` and `agent.yaml` to
the monitored host (the generated `agent.yaml` expects them under
`/var/lib/correlic/certs`, the layout of the Linux packages):

```sh
for f in ca.crt client.crt client.key agent.yaml; do
  kubectl -n correlic exec deploy/backend-api -- cat /certs/$f > ./$f
done
```

A host outside the cluster needs the backend planes reachable with mTLS end
to end — an HTTP Ingress cannot do that. `base/backend-external.example.yaml`
exposes them as LoadBalancer services; the address must be one of the
server certificate's SANs (`CERT_EXTRA_SANS`) and the URLs in `agent.yaml`
must point at it. An agent inside the cluster (a DaemonSet, privileged with
`/sys/kernel` and host PID) can use the in-cluster service names as they are.

## Upgrading

1. Change the tag in `base/kustomization.yaml` (`images:`).
2. Delete the completed Job — a Job's spec is immutable — and apply again:

   ```sh
   kubectl -n correlic delete job correlic-bootstrap
   kubectl apply -k install/kubernetes/base      # or overlays/graph
   ```

   The Job re-runs `migrate up` only; the `.bootstrapped` marker in the
   certs volume skips everything else. The backend image's entrypoint also
   applies migrations on start, so a plane that starts first does not wait
   for the Job.

## Operations

Health endpoints, logs, metrics (`/metrics` on both planes), retention,
backups and the upgrade procedure are documented in
`backend/docs/OPERATIONS.md`. In this layout: `kubectl -n correlic logs
deploy/backend-api` (and `backend-tel`, `ui`, `ui-proxy`), PostgreSQL
backups with `kubectl -n correlic exec postgres-0 -- pg_dump -U correlic
correlic > correlic.sql`.

## Limitations

- **Single node for the certificate consumers.** The certs volume is
  `ReadWriteOnce`, so the bootstrap Job, both backend planes and `ui-proxy`
  must run on the same node. They carry a required pod affinity on
  `correlic.io/certs=true` to guarantee it, and the Deployments use the
  `Recreate` strategy. For a multi-node setup move the files into a Secret
  after the first bootstrap and mount that instead of the PVC:

  ```sh
  kubectl -n correlic create secret generic correlic-certs \
    --from-file=ca.crt --from-file=server.crt --from-file=server.key \
    --from-file=client.crt --from-file=client.key   # files fetched as above
  ```

  then replace the `persistentVolumeClaim` volume in `backend-api.yaml`,
  `backend-tel.yaml` and `ui-proxy.yaml` with `secret: {secretName:
  correlic-certs}` and drop the affinity.
- **No high-availability claims.** Every workload is a single replica; the
  bundled PostgreSQL and Neo4j are single-node StatefulSets without
  replication. Use a managed PostgreSQL (`postgres.yaml` says how) for data
  you cannot afford to lose; the certs volume and `.bootstrapped` marker
  belong in your backup too.
- **API plane probes are TCP.** `backend-api` requires a client certificate
  on every TLS handshake, which the kubelet cannot present, so its probes
  open a TCP connection instead of fetching `/health`. The telemetry plane
  verifies client certificates only when presented and is probed over HTTPS
  on `/health` and `/readiness`.
- **One root container.** The bootstrap Job's `certs` init container runs
  as root to install `openssl` into its ephemeral filesystem; everything
  else runs as a non-root user. The namespace enforces the `baseline` Pod
  Security level for that reason.
- **Root filesystems.** The backend planes, `ui-proxy` and `ui` run with
  `readOnlyRootFilesystem`; PostgreSQL and Neo4j write to their image
  filesystem at startup and do not.

## Validation

Every file parses with PyYAML; `kubectl kustomize` renders the base (15
objects) and the graph overlay (17 objects); the rendered output passes
`kubeconform -strict` against the Kubernetes 1.30 schemas. `kubectl apply
--dry-run=client -k` needs an API server for REST mapping and was not run
against a cluster, so the manifests have not been applied to a live cluster
as part of this change — treat the first deployment as a smoke test.
