package io.kestra.plugin.gcp.shared;

import java.util.List;

import io.kestra.core.models.property.Property;

import io.swagger.v3.oas.annotations.media.Schema;
import io.kestra.core.models.annotations.PluginProperty;

public interface GcpInterface {
    @Schema(title = "The GCP project ID")
    @PluginProperty(group = "connection")
    Property<String> getProjectId();

    @Schema(
        title = "The GCP service account",
        description = "When unset or rendered to an empty value, Application Default Credentials are used (e.g. GOOGLE_APPLICATION_CREDENTIALS or the runtime's attached identity)."
    )
    @PluginProperty(secret = true, group = "connection")
    Property<String> getServiceAccount();

    @Schema(title = "The GCP service account to impersonate")
    @PluginProperty(secret = true, group = "connection")
    Property<String> getImpersonatedServiceAccount();

    @Schema(
        title = "OIDC token for Workload Identity Federation",
        description = "When set together with `workloadIdentityAudience`, the token is exchanged at Google STS for federated credentials and no service account key is needed: Google verifies it against the identity provider that issued it. " +
            "Use `{{ oidcToken(audience='…') }}` to have Kestra Enterprise mint one for the running execution. " +
            "Combine with `impersonatedServiceAccount` to act as a service account the pool may impersonate, and set `projectId` explicitly since no key file carries it. Cannot be combined with `serviceAccount`."
    )
    @PluginProperty(secret = true, group = "connection")
    default Property<String> getWorkloadIdentityToken() {
        return null;
    }

    @Schema(
        title = "Audience of the Workload Identity Federation provider",
        description = "The full resource name of the workload identity pool provider, `//iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>`. Required with `workloadIdentityToken`, and must match the `aud` claim of the token."
    )
    @PluginProperty(group = "connection")
    default Property<String> getWorkloadIdentityAudience() {
        return null;
    }

    @Schema(title = "The GCP scopes to be used")
    @PluginProperty(group = "connection")
    Property<List<String>> getScopes();

    /**
     * Whether the project id may be inferred from Application Default Credentials that happen to
     * resolve to a service-account key (e.g. {@code GOOGLE_APPLICATION_CREDENTIALS}) when neither an
     * explicit {@code projectId} nor an explicit {@code serviceAccount} is configured.
     * <p>
     * plugin-gcp (OSS) infers it, its historical behaviour, kept here so the extraction is a no-op
     * for OSS. plugin-ee-gcp overrides this to {@code false} so that such a run keeps failing
     * explicitly rather than silently adopting the host key file's project. An explicitly-configured
     * {@code serviceAccount} always allows inference regardless of this flag.
     * <p>
     * Not a configurable plugin property: it does not follow getter naming, so it is never
     * serialized or documented in the schema.
     */
    default boolean inferProjectIdFromApplicationDefault() {
        return true;
    }
}
