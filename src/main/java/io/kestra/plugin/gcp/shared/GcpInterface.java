package io.kestra.plugin.gcp.shared;

import java.util.List;

import io.kestra.core.models.property.Property;

import io.swagger.v3.oas.annotations.media.Schema;
import io.kestra.core.models.annotations.PluginProperty;

public interface GcpInterface {
    // TODO(#2): these connection properties are spread across three groups (connection / execution /
    // advanced) inherited from the pre-extraction plugins. Regroup them consistently under
    // "connection" in a change coordinated across the kernel, plugin-gcp and plugin-ee-gcp.
    // https://github.com/kestra-io/plugin-gcp-lib/issues/2
    @Schema(title = "The GCP project ID")
    @PluginProperty(group = "connection")
    Property<String> getProjectId();

    @Schema(title = "The GCP service account")
    @PluginProperty(secret = true, group = "execution")
    Property<String> getServiceAccount();

    @Schema(title = "The GCP service account to impersonate")
    @PluginProperty(secret = true, group = "advanced")
    Property<String> getImpersonatedServiceAccount();

    @Schema(title = "The GCP scopes to be used")
    @PluginProperty(group = "advanced")
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
