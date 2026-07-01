# Engineering Guidelines

The distilled reference behind `config.yaml`. Commands point here; they don't restate it.

## Build-vs-adopt hierarchy (EDF)

Default decision order — moving **down** requires explicit justification:

```
Rent infrastructure  >  Adopt OSS  >  Extend OSS  >  Fork OSS  >  Build new
```

- **Rent** — compute, storage, networking, CDN/DNS, clusters. Infra is never "proprietary software."
- **Adopt** — OSS meets ~90% of needs → configure, don't rewrite. Contribute upstream where possible.
- **Extend** — gaps remain → add via plugin / middleware / adapter / wrapper. Preserve upstream compatibility.
- **Fork** — only if upstream is unmaintained, divergence is unavoidable, and extension/contribution aren't viable. Record maintenance burden + sync strategy.
- **Build** — last resort: no viable OSS, architecturally incompatible, or it's genuinely your differentiating value.

### Maturity rubric (score OSS candidates)

| Criterion             | Weight |
| --------------------- | ------ |
| Feature coverage      | 30%    |
| Extensibility         | 20%    |
| Maintenance activity  | 15%    |
| Documentation         | 10%    |
| Community size        | 10%    |
| Security history      | 10%    |
| License compatibility | 5%     |

Hard rejects (override score): active security risk · incompatible license · abandoned maintenance.

### Decision matrix

| Situation                          | Default |
| ---------------------------------- | ------- |
| Infrastructure                     | Rent    |
| OSS ≥ 90% match                    | Adopt   |
| OSS 70–90% match                   | Extend  |
| Small gap, OSS close               | Fork    |
| No OSS / strategic differentiation | Build   |
| Commodity functionality            | Adopt   |

Evaluate **lifecycle** cost (integration, upgrades, patching, ops), not just first build. Revisit decisions every 6–12 months — none are permanent.

## Abstraction layers

| Layer | Artifact              | Holds                                                      | Never holds           |
| ----- | --------------------- | ---------------------------------------------------------- | --------------------- |
| WHAT  | `specs/<cap>/spec.md` | observable behavior, contracts, invariants                 | tech, structure       |
| HOW   | `design.md`           | core/adapter structure, dependency direction, tool choices | behavior redefinition |
| DO    | `tasks.md` + code     | the pinned implementation                                  | new rules or scope    |

- One canonical design — decide, don't list variants.
- Composable core; every surface is a thin adapter (no logic, no state).
- Dependencies point **inward**: adapters → application → domain core. Core runs with no surface present.

## Externalize native-format content (data is not code)

Content that has its own format and tooling lives in a file of that format — never
embedded as a string literal in source. The code references or loads it; it does not
inline it.

Applies to: SQL/migrations, schema DDL, YAML/TOML/JSON/`.env` config, HTML/email/report
templates, GraphQL/Protobuf/OpenAPI schemas, prompt templates, CSS, regex catalogs, and
any multi-line literal that is really data with a grammar.

- **Why** — native files get syntax highlighting, linting, formatting, diffs, and
  validation in CI; embedding them as strings hides the data from every one of those
  tools and mixes the DO layer (logic) with content that is really a contract.
- **Keep the native extension** (`.sql`, `.yaml`, `.toml`, `.html`, `.graphql`) so
  editors and CI recognize it. Load it via the format's mature parser/loader — per the
  build-vs-adopt hierarchy, don't hand-roll parsing of a standard format.
- **Loading is an adapter concern.** Read at runtime, or embed at build time (e.g. a
  compile-time include), behind a loader in the adapter layer — never reach into files
  from the core.
- **Exception** — short, one-line literals that are not independently meaningful (a
  single key, a format string, a trivial query) stay inline. The line is whether the
  content has its own grammar/tooling or is large enough to be data, not code.

## Single source of truth for values

Every value is defined once and referenced — never duplicated as a magic literal. Where
the one definition lives depends on what the value is:

- **Constants** (domain invariants fixed at build time — limits, status codes, keys,
  defaults) live **next to the concept that owns them** in the core, exported for reuse.
  Locality over a global bucket: a `constants` god-module that collects unrelated values
  couples every caller to it and rots — split by owning concept instead.
- **Config** (runtime- or environment-tunable values — URLs, timeouts, feature flags) is
  **centralized in one external native-format file** (see _Externalize native-format
  content_) and read through a single config adapter. The core receives typed, validated
  values — never raw `env`/file lookups scattered through the code.
- **Secrets are not config.** Committed config files hold non-secret values only. Secrets
  (keys, tokens, passwords, connection strings) are injected at runtime from the
  environment or a secret manager, referenced by key, and **never written to source or
  VCS** — not even in an example file with a real value. The config adapter resolves them;
  the core only ever sees the resolved value.
- **No magic literals** in logic or tasks. A bare number or string with meaning gets a
  named definition at its canonical home; repetition of the same literal is a defect.

The test: changing a value should mean editing exactly one place, and that place should
be the one an owner would look first.

## Document taxonomy

Map docs to a canonical type — don't invent categories:

- **RFC** — proposed change (here: a `proposal` + `specs`). Lifecycle: **draft → approved**.
- **ADR** — one architectural decision + context/tradeoffs (here: build-vs-adopt blocks in `design.md`).
- **ADD** — system/service architecture · **TDD** — feature/subsystem design.
- **Runbook** — ops procedures · **Postmortem** — post-incident learning · **Threat Model** — security analysis.

Separation of concerns: ADR ≠ design doc · RFC ≠ implementation plan · Runbook ≠ postmortem.
