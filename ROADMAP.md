# Netbase Roadmap

This roadmap tracks the work to harden Netbase and grow it from a data-generation
framework into one that closes the loop with tuning and detection workflows.

Legend: ✅ done · 🔜 planned · 🧪 needs validation

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

## Phase 2 — Enrich observables 🔜

Additive, high-signal fields that detection keys on. Each is independently
shippable.

- 🔜 **flow.zeek** — connection **duration** numstats (internal/external) + a
  long-connection counter over a `&redef` threshold.
- 🔜 **geo.zeek** (new) — cardinality of unique **countries** and **ASNs** for
  external peers (`lookup_location` / `lookup_autonomous_system`). Enables
  "new country / new ASN" detection in Phase 3.
- 🔜 **ssl.zeek** (new) — **JA3/JA4** cardinality, **SNI** cardinality, self-signed /
  validation-failed counts, certificate-age stats.
- 🔜 **dns.zeek** — query-name length stats, NXDOMAIN ratio, TXT counts (DGA /
  tunneling signal).
- 🔜 **beacon.zeek** (new) — per `(src → dst:port)` inter-arrival regularity
  (coefficient of variation) to flag periodic beaconing.
  - **Opt-out:** disabled by default behind `Netbase::enable_beaconing = F &redef`.
  - **Memory controls:** `&redef` caps on tracked tuples per host and samples per
    tuple, a `&create_expire` idle timeout on the tracking table, and an option to
    restrict tracking to external destinations only.

## Phase 3 — Detection & tuning integration 🔜

The feedback loop the README describes but never implemented. Ships in
**learning / suppressed mode by default** so it is safe to deploy.

- 🔜 **baseline.zeek** (new) — persistent Broker/SQLite store of running per-host and
  per-peer-group stats (Welford mean/variance + observed categorical sets: ports,
  ASNs, software, roles). Exposes `Netbase::is_anomalous(ip, field, value)` and
  `Netbase::zscore(...)`.
- 🔜 **detect.zeek** (new) — on `log_observation`, raise Zeek **Notices**:
  - numeric: z-score over a `&redef` threshold (conn counts, ext bytes, durations);
  - categorical "first seen": new external ASN/country, new listening port, new
    software version, first-time SMB/RDP/SSH **server** role.
- 🔜 **Tuning loop** — a `&redef` learning window during which baselines build but
  Notices stay suppressed, plus an analyst **allowlist** (`approved_observables.tsv`,
  Input framework) to suppress known-good per host/group. That file is the tuning
  artifact; combined with Zeek's native Notice suppression.
- 🔜 **Peer-group cold-start** — use Phase 1 labels (role/OS) so a new host is scored
  against its peer group until it has its own history.
- 🔜 **SIEM export** — documented ECS field mapping for `netbase.log` + a JSON
  log-policy toggle, so baselines and anomaly Notices correlate downstream.

---

## Sequencing

```
Phase 0 ─┬─ Phase 1 (correctness)   ← gate: CI green, all modules load
         └─ Phase 2 (enrichment)    ← overlaps; each field independently shippable
                       └─ Phase 3 (detection) ← needs labels (P1) + geo/ssl (P2)
```
