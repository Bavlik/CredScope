# compose-dependency-topology-internal-no-port

**Scenario.** `worker` holds `WORKER_TOKEN` and declares `depends_on:
queue`. Both services are attached only to an internal, non-default network;
neither publishes a host port.

**Threat or safety property.** Dependency and network-topology edges must
be recorded as static structural facts, distinct from and never conflated
with published-port exposure. This case proves a credential-holding service
with real dependency structure but no port publication does not spuriously
trigger `CRD303`.

**Relevant inputs.** `repository/compose.yml`.

**Expected behavior.** `CRD301` matches `WORKER_TOKEN`. A `depends_on` edge
connects `worker` to `queue` with `network_topology_only` evidence.

**Expected non-behavior.** `CRD303` ("Credential reaches published host
port") does not match — no port is published anywhere in this fixture.
`queue` is not classified as holding or receiving `WORKER_TOKEN`.

**Covered rule/evidence concepts.** `CRD301`; `depends_on` edge;
`network_topology_only` evidence kind.

**Why the fixture is safe.** `WORKER_TOKEN` is only ever a `${VAR}`
reference.
