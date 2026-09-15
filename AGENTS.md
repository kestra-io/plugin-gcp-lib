# Kestra GCP Lib

## What

- Shared kernel of GCP authentication/connection base classes, consumed by both `plugin-gcp`
  (OSS) and `plugin-ee-gcp` (EE), so the two plugins no longer duplicate the same auth code.
- Provides classes under `io.kestra.plugin.gcp.shared`: `GcpInterface`, `CredentialService`,
  `AbstractTask`.

## Why

- What user problem does this solve? `plugin-gcp` and `plugin-ee-gcp` each maintained their own
  copy of GCP credential resolution (service account, impersonation, scopes, project id
  inference), which drifted over time and had to be fixed twice for the same bug.
- Why would a team adopt this plugin in a workflow? It is not used directly in flows; it is a
  library dependency that GCP task/trigger authors build on to get consistent, tested
  authentication behavior for free.
- What operational/business outcome does it enable? A single place to fix GCP auth bugs and add
  auth features (e.g. impersonation, scopes) that both the OSS and EE GCP plugins pick up.

## How

### Architecture

Single-module library. Source packages under `io.kestra.plugin.gcp`:

- `shared`

### Key Classes

- `io.kestra.plugin.gcp.shared.GcpInterface` — contract for GCP connection properties
  (`projectId`, `serviceAccount`, `impersonatedServiceAccount`, `scopes`).
- `io.kestra.plugin.gcp.shared.CredentialService` — resolves `GoogleCredentials` from a
  `GcpInterface` (service account key, application default, scopes, impersonation) and infers the
  effective project id via `resolveProjectId`.
- `io.kestra.plugin.gcp.shared.AbstractTask` — base `Task` implementing `GcpInterface`, exposing
  `credentials(RunContext)` to concrete GCP tasks.

### Project Structure

```
plugin-gcp-lib/
├── src/main/java/io/kestra/plugin/gcp/shared/
├── src/test/java/io/kestra/plugin/gcp/shared/
├── build.gradle
└── README.md
```

## Local rules

- Base the wording on the implemented packages and classes, not on template README text.
- Scope stays limited to auth/connection shared code; OSS-only helpers (validators,
  `OauthAccessToken`, GCS/BigQuery services, etc.) must stay in `plugin-gcp`, not here.

## References

- https://kestra.io/docs/plugin-developer-guide
- https://kestra.io/docs/plugin-developer-guide/contribution-guidelines
