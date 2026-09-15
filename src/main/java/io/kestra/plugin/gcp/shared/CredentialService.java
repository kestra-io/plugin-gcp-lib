package io.kestra.plugin.gcp.shared;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Map;

import com.fasterxml.jackson.core.type.TypeReference;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ImpersonatedCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;

import io.kestra.core.exceptions.IllegalVariableEvaluationException;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContext;
import io.kestra.core.serializers.JacksonMapper;

public final class CredentialService {
    private CredentialService() {
    }

    /**
     * Resolves the credentials authenticating as the configured service account (or application
     * default credentials), with scopes applied, before any impersonation is layered on top.
     * {@link #resolveProjectId} must be called against these source credentials rather than the
     * result of {@link #credentials}, since {@link ImpersonatedCredentials} does not carry a
     * project id of its own.
     */
    public static GoogleCredentials sourceCredentials(RunContext runContext, GcpInterface gcpInterface)
        throws IllegalVariableEvaluationException, IOException {
        GoogleCredentials credentials;

        if (gcpInterface.getServiceAccount() != null) {
            String serviceAccount = runContext.render(gcpInterface.getServiceAccount()).as(String.class)
                .orElseThrow(() -> new IllegalArgumentException("serviceAccount rendered to an empty value"));
            var byteArrayInputStream = new ByteArrayInputStream(serviceAccount.getBytes(StandardCharsets.UTF_8));
            credentials = ServiceAccountCredentials.fromStream(byteArrayInputStream);
            var logger = runContext.logger();

            if (logger.isTraceEnabled()) {
                byteArrayInputStream.reset();
                Map<String, String> jsonKey = JacksonMapper.ofJson().readValue(
                    byteArrayInputStream,
                    new TypeReference<>() {
                    }
                );
                if (jsonKey.containsKey("client_email")) {
                    logger.trace(" • Using service account: {}", jsonKey.get("client_email"));
                }
            }
        } else {
            credentials = GoogleCredentials.getApplicationDefault();
        }

        var renderedScopes = runContext.render(gcpInterface.getScopes()).asList(String.class);
        if (!renderedScopes.isEmpty()) {
            credentials = credentials.createScoped(renderedScopes);
        }

        return credentials;
    }

    public static GoogleCredentials credentials(RunContext runContext, GcpInterface gcpInterface)
        throws IllegalVariableEvaluationException, IOException {
        return credentials(runContext, gcpInterface, sourceCredentials(runContext, gcpInterface));
    }

    /**
     * Wraps already-resolved source credentials with impersonation when configured, without
     * re-deriving them. Used by {@link #credentials(RunContext, GcpInterface)} and by callers
     * (e.g. {@code AbstractTask}) that already hold the source credentials, e.g. to resolve the
     * project id against them.
     */
    static GoogleCredentials credentials(RunContext runContext, GcpInterface gcpInterface, GoogleCredentials sourceCredentials)
        throws IllegalVariableEvaluationException, IOException {
        if (gcpInterface.getImpersonatedServiceAccount() == null) {
            return sourceCredentials;
        }

        var renderedScopes = runContext.render(gcpInterface.getScopes()).asList(String.class);
        return ImpersonatedCredentials.create(
            sourceCredentials,
            runContext.render(gcpInterface.getImpersonatedServiceAccount()).as(String.class)
                .orElseThrow(() -> new IllegalArgumentException("impersonatedServiceAccount rendered to an empty value")),
            null,
            renderedScopes.isEmpty() ? new ArrayList<>() : renderedScopes,
            3600
        );
    }

    /**
     * Resolves the effective GCP project id for the given credentials: the explicitly configured
     * one if present, otherwise the project id inferred from {@code credentials} when they are
     * {@link ServiceAccountCredentials}. This helper is pure — it never mutates {@code gcpInterface}
     * or {@code credentials} — regardless of how those credentials were obtained; callers must pass
     * the pre-impersonation source credentials (see {@link #sourceCredentials}) to get a non-null
     * result when impersonation is configured.
     */
    public static Property<String> resolveProjectId(GcpInterface gcpInterface, GoogleCredentials credentials) {
        if (gcpInterface.getProjectId() != null) {
            return gcpInterface.getProjectId();
        }
        if (credentials instanceof ServiceAccountCredentials serviceAccountCredentials
            && serviceAccountCredentials.getProjectId() != null) {
            return Property.ofValue(serviceAccountCredentials.getProjectId());
        }
        return gcpInterface.getProjectId();
    }
}
