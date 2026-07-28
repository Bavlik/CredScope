# compose-topology-does-not-imply-flow-regression

**Scenario.** `api` holds `API_TOKEN` and declares `depends_on: cache`.
`cache` has no environment, secret, or credential reference of its own.

**Threat or safety property.** This is a dedicated regression case for the
exact boundary docs/ARCHITECTURE.md describes: "an API dependency on Redis
does not imply the credential was transmitted to Redis." Dependency and
network-topology edges are structural facts, not evidence of data flow, and
must never be conflated with `available_to_service`/`configured_in`-style
confirmed edges.

**Relevant inputs.** `repository/compose.yml`.

**Expected behavior.** `CRD301` matches `API_TOKEN` for `api` only. A
`depends_on` edge connects `api` to `cache` with `network_topology_only`
evidence. `cache` has no credential of its own in the credentials list.

**Expected non-behavior.** `cache` never receives a
`confirmed_static_data_flow` edge for `API_TOKEN`, and no rule claims the
credential reached `cache`. The frozen `expected.json`/`expected.sarif`
make this an enforced regression guard, not just documentation.

**Covered rule/evidence concepts.** `CRD301`; `depends_on` edge;
`network_topology_only` vs. `confirmed_static_data_flow` evidence kind
separation.

**Why the fixture is safe.** `API_TOKEN` is only ever a `${VAR}` reference.
