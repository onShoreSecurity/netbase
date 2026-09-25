# Netbase Roadmap

This roadmap tracks the work to harden Netbase and grow it from a data-generation
framework into one that closes the loop with tuning and detection workflows.

Legend: ✅ done · 🔜 planned · 🧪 needs validation

## Deployment architecture (drives the design)

Netbase runs as **several independent Zeek worker processes load-balanced over the
same traffic (AF_PACKET fanout), with no cluster**. Implications:

- There is no Broker/proxy tier. Every worker takes the `! Cluster::is_enabled()`
  path and aggregates its own slice in-process, then writes its own `netbase.log`.
  Per-host observables for an interval are therefore **split across workers and must
  be merged downstream** (sum counts, union cardinality sets) — this is unchanged by
  the work here and already how the deployment consumes the logs.
- Anything needing a single, consistent cross-worker view — **rolling baselines
  (Phase 3)** and **beaconing series (Phase 2)** — cannot live in worker memory.
- The sensor has a **local Redis** instance. That is the shared store. `store.zeek`
  (✅, opt-in) wraps Zeek 7.2+'s Storage framework Redis backend so each worker opens
  its own connection to the one Redis dataset. Note: get/put is a plain key→value
  interface with no atomic list ops, so series that multiple workers append to are
  designed to avoid read-modify-write races (per-worker keys + aggregation, not
  shared mutable lists).

---

## Phase 0 — Modernize & package ✅

Foundation work so the package installs and validates cleanly on current Zeek.

- ✅ Migrate `*.bro` → `*.zeek` and `bro_init` → `zeek_init`.
- ✅ `__load__.zeek` now loads every working module (main, labels, flow, software,
  dns, http, ssh, ftp, weird, stats).
- ✅ `zkg.meta` added so the package installs via `zkg install`.
- ✅ `testing/` btest smoke test + `.github/workflows/ci.yml` that parse-checks the
  package on every push (this is the regression gate for the fixes below).

## Phase 1 — Correctness ✅

Repair the modules that were dormant because they did not compile or silently
dropped data.

- ✅ **dns.zeek** — rewritten: valid event handler, real DNS observables
  (client/server roles, authoritative vs recursive answers, NXDOMAIN sent/received,
  rejected queries, internal/external unique-RR cardinality). Previously
  non-compilable.
- ✅ **labels.zeek** — replaced the broken, externally-dependent draft with a
  self-contained static CIDR labeling implementation (`cidr_labels` redef + optional
  `cidr_labels_file` via the Input framework). Emits `ip_labels` per host — the hook
  Phase 3 peer-group comparison depends on.
- ✅ **ssh.zeek** — fixed field mapping: `ssh_as_client`/`ssh_as_server` now
  increment their own counters instead of the auth-fail counters.
- ✅ **flow.zeek** — wired up three dropped observables (`out_orig_conns`,
  `int_succ_conns`, `inbound_server_conns`) and removed trailing `fallthrough`
  statements at the end of switches.
- ✅ **weird.zeek** — fixed the orig/resp mix-up and added the missing `SEND()`
  calls (weird observables were never delivered before).
- ✅ **http/ssh/ftp/weird** — monitoring gate aligned to `Netbase::is_monitored()`,
  matching flow/dns and preventing proxy-side runtime errors on non-monitored IPs.
- ✅ **stats.zeek** — `CLUSTER_NODE` now falls back to `standalone`.
- ✅ Removed the orphaned, buggy `utils.zeek` (dead duplicate of `numstats`).

## Phase 2 — Enrich observables (worker-local) ✅ / beaconing 🔜

Additive, high-signal fields that detection keys on. The first four aggregate
downstream exactly like existing observables (no shared state needed) and shipped
together:

- ✅ **flow.zeek** — connection **duration** numstats (internal/external,
  `int_dur_*` / `out_dur_*`) + a `long_conns` counter over the `long_conn_threshold`
  (`&redef`, default 1h).
- ✅ **geo.zeek** (new) — cardinality of unique **countries** (`ext_country_cnt`) and
  **ASNs** (`ext_asn_cnt`) for external peers (`lookup_location` /
  `lookup_autonomous_system`; degrades to no-op without GeoIP DBs). Enables
  "new country / new ASN" detection in Phase 3.
- ✅ **ssl.zeek** (new) — **SNI** cardinality (`tls_sni_cnt`), deprecated-TLS-version
  count (`tls_old_version_conns`), and certificate **validation-failure** count
  (`tls_validation_failures`). Base-only (no JA3/JA4 package dependency).
- ✅ **dns.zeek** — query-name **length** stats (`dns_qname_len_*`) and **TXT**-query
  count (`dns_txt_queries`) for DGA / tunneling signal. (NXDOMAIN ratio is derivable
  downstream from the existing `dns_nxdomain_*` counters.)

Deferred — needs the shared store, so it lands with Phase 3:

- 🔜 **beacon.zeek** (new) — per `(src → dst:port)` inter-arrival regularity
  (coefficient of variation) to flag periodic beaconing. **Cannot** be done per-worker:
  flow-hash fanout scatters a host's repeat connections across workers, so no single
  worker sees the full series. Will key per-tuple series in **Redis via `store.zeek`**
  (per-worker contribution keys to avoid append races), then score periodicity.
  - **Opt-out:** disabled by default behind `Netbase::enable_beaconing = F &redef`.
  - **Memory / cost controls:** `&redef` caps on tracked tuples per host and samples
    per tuple, an idle expiry on the tracking state, an option to restrict tracking to
    external destinations only, and a Redis-key TTL so abandoned series self-clean.

### JA3/JA4 (optional follow-up)
TLS fingerprint cardinality (JA3/JA4) is high value but requires the external
`zeek/ja3` (and JA4) packages. Add as an optional module guarded on those packages so
the core stays dependency-free.

## Phase 3 — Detection & tuning integration (first-seen ✅ / numeric 🔜)

The feedback loop the README describes but never implemented. Ships in
**learning / suppressed mode by default** so it is safe to deploy. Built on the
**Redis shared store** (`store.zeek`) so all parallel workers share one baseline.

All three modules below are **opt-in** — they require a Zeek built with the Redis
storage backend, so they are deliberately excluded from `__load__.zeek` and from CI.
Enable on the sensor with:

```
@load netbase/detect          # pulls in baseline + store
redef Netbase::learning_mode = F;   # only after the baseline has warmed up
```

- ✅ **store.zeek** (foundation) — opt-in Redis backend wrapper (Zeek 7.2+ Storage
  framework) giving every worker a connection to the one local Redis dataset.
- ✅ **baseline.zeek** — Redis-backed **first-seen** state. Uses `Storage::put` with
  `$overwrite=F`, which is an **atomic test-and-set** (Redis SETNX): exactly one
  worker wins the race for a given key, so there is no read-modify-write window and
  a value is reported at most once fleet-wide. Keys carry a `baseline_ttl` (30d
  default) so stale "normal" ages out, with `refresh_ttl_on_hit` sliding the TTL
  forward for activity that stays normal.
- ✅ **detect.zeek** — raises Notices on `log_observation` for first-seen
  categorical values: `New_External_ASN`, `New_External_Country`,
  `New_External_Port`, `New_Internal_Port`, `New_Software`. Bounded by
  `max_checks_per_dimension` (cap is logged via Reporter, never silent).
- ✅ **Tuning loop** — `learning_mode` (default **T** = populate but never alert)
  plus a `learning_window` warm-up so a restart does not alert on the world, and a
  `Netbase::suppressions` allowlist (redef set or a live-reread TSV) accepting
  `dim=value` globally or `ip|dim=value` per host. That file is the analyst tuning
  artifact; it composes with Zeek's native Notice suppression via `$identifier`.

### Why numeric anomaly scoring is not in this cut 🔜

Under the no-cluster, AF_PACKET-fanout deployment, **no single worker sees all of a
host's traffic**, so a worker's `total_conns` / `out_orig_bytes_sent` for an interval
is a *fraction* of the true value — and the fraction varies with flow-hash
distribution. Computing a z-score against a per-worker value would score noise and
generate false positives.

First-seen does not have this problem: it is a set-membership test where a partial
view can only ever *miss* a value (delaying an alert), never fabricate one.

The numeric path therefore needs a single aggregation point. Options, in preference
order:

1. **Aggregate downstream** (recommended) — the SIEM/pipeline already merges
   per-worker `netbase.log` rows; run z-scoring there, where the merged value lives.
2. **Redis-side merge** — workers write per-worker interval keys
   (`agg:<metric>:<ip>:<interval>:<worker>`); a single reader sums them per interval
   and updates the running Welford stats. Avoids the append race because each worker
   owns its own key.

- 🔜 **beacon.zeek** — deferred for the same reason: flow-hash fanout scatters a
  host's repeat connections, so inter-arrival series must be reassembled through
  Redis (per-worker contribution keys, then score periodicity). Keeps the
  `enable_beaconing = F` opt-out and the per-host/per-tuple caps + TTLs.
- 🔜 **Peer-group cold-start** — use Phase 1 labels (role/OS) so a new host is scored
  against its peer group until it has its own history.
- 🔜 **SIEM export** — documented ECS field mapping for `netbase.log` + a JSON
  log-policy toggle, so baselines and anomaly Notices correlate downstream.

---

## Validation status

| Area | Status |
|---|---|
| Phase 0–2 (default-loaded modules) | ✅ CI green — parse-check + btest on `zeek/zeek:latest` (Zeek 8), merged in PR #1 |
| `store.zeek`, `baseline.zeek`, `detect.zeek` | 🧪 **Not covered by CI** — the stock Zeek image is built without the Redis storage backend. Needs a first run on a sensor with a Redis-enabled Zeek. |

Specifically worth confirming on first sensor deploy: the Redis backend enum constant
is referenced as `Storage::STORAGE_BACKEND_REDIS` (registered from C++, not visible in
the script docs). It is exposed as `Netbase::redis_backend_tag &redef` precisely so it
can be corrected without editing the module if the name differs on your build.

## Sequencing

```
Phase 0 ─┬─ Phase 1 (correctness)   ← gate: CI green, all modules load
         └─ Phase 2 (enrichment)    ← overlaps; each field independently shippable
                       └─ Phase 3 (detection) ← needs labels (P1) + geo/ssl (P2)
                                    first-seen ✅ · numeric/beaconing need aggregation
```
