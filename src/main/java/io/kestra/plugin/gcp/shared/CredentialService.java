package io.kestra.plugin.gcp.shared;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

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
     * The resolved GCP connection for a {@link GcpInterface}: the credentials to authenticate with
     * (already impersonated when configured) together with the effective project id.
     * <p>
     * These two are resolved together on purpose. The project id must be read from the
     * pre-impersonation source credentials, since {@link ImpersonatedCredentials} carries none of its
     * own, so exposing a single call that returns both removes the recurring footgun of resolving the
     * project id against the already-impersonated result and silently getting {@code null}.
     */
    public record GcpConnection(GoogleCredentials credentials, Property<String> projectId) {
    }

    /**
     * Resolves the GCP connection for the given interface: builds the source credentials (service
     * account key or Application Default Credentials, with scopes applied), reads the effective
     * project id from them, then layers impersonation on top when configured. This is the only entry
     * point; the intermediate steps are intentionally not exposed so callers cannot recombine them
     * incorrectly.
     */
    public static GcpConnection connection(RunContext runContext, GcpInterface gcpInterface)
        throws IllegalVariableEvaluationException, IOException {
        List<String> scopes = runContext.render(gcpInterface.getScopes()).asList(String.class);
        Optional<String> serviceAccount = renderNonBlank(runContext, gcpInterface.getServiceAccount());
        if (gcpInterface.getServiceAccount() != null && serviceAccount.isEmpty()) {
            runContext.logger().warn("serviceAccount rendered to an empty value, using Application Default Credentials");
        }
        GoogleCredentials sourceCredentials = sourceCredentials(runContext, serviceAccount, scopes);
        Property<String> projectId = resolveProjectId(gcpInterface, serviceAccount.isPresent(), sourceCredentials);
        GoogleCredentials credentials = impersonate(runContext, gcpInterface, sourceCredentials, scopes);
        return new GcpConnection(credentials, projectId);
    }

    /**
     * Renders {@code property} and returns its value, or empty when the property is unset or renders
     * to a blank string. An expression such as {@code "{{ outputs.x.key | default(null) }}"} renders
     * to {@code ""} rather than {@code null}, so it must be treated the same as an unset property.
     */
    static Optional<String> renderNonBlank(RunContext runContext, Property<String> property)
        throws IllegalVariableEvaluationException {
        if (property == null) {
            return Optional.empty();
        }
        return runContext.render(property).as(String.class).filter(value -> !value.isBlank());
    }

    /**
     * Builds the credentials authenticating as the rendered service account key (or application default
     * credentials when it is absent), with {@code scopes} applied, before any impersonation is layered
     * on top.
     */
    static GoogleCredentials sourceCredentials(RunContext runContext, Optional<String> serviceAccount, List<String> scopes)
        throws IOException {
        GoogleCredentials credentials;

        if (serviceAccount.isPresent()) {
            var byteArrayInputStream = new ByteArrayInputStream(serviceAccount.get().getBytes(StandardCharsets.UTF_8));
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

        if (!scopes.isEmpty()) {
            credentials = credentials.createScoped(scopes);
        }

        return credentials;
    }

    /**
     * Wraps the source credentials with impersonation when {@code impersonatedServiceAccount} is set,
     * reusing the already-rendered {@code scopes}; returns them unchanged otherwise.
     */
    static GoogleCredentials impersonate(RunContext runContext, GcpInterface gcpInterface, GoogleCredentials sourceCredentials, List<String> scopes)
        throws IllegalVariableEvaluationException {
        if (gcpInterface.getImpersonatedServiceAccount() == null) {
            return sourceCredentials;
        }

        return ImpersonatedCredentials.create(
            sourceCredentials,
            runContext.render(gcpInterface.getImpersonatedServiceAccount()).as(String.class)
                .orElseThrow(() -> new IllegalArgumentException("impersonatedServiceAccount rendered to an empty value")),
            null,
            scopes.isEmpty() ? new ArrayList<>() : scopes,
            3600
        );
    }

    /**
     * Resolves the effective GCP project id: the explicitly configured one if present, otherwise the
     * project id carried by {@code credentials} when they are {@link ServiceAccountCredentials}. Pure:
     * never mutates {@code gcpInterface} or {@code credentials}. Callers must pass the
     * pre-impersonation source credentials to get a non-null result when impersonation is configured.
     * <p>
     * Inference from credentials that come from Application Default Credentials (no explicit
     * {@code serviceAccount}) is gated on {@link GcpInterface#inferProjectIdFromApplicationDefault()}:
     * plugin-gcp allows it (its historical behaviour), plugin-ee-gcp does not. An explicit
     * {@code serviceAccount} always allows it. {@code fromExplicitServiceAccount} must reflect the
     * rendered value, so a {@code serviceAccount} expression rendering to blank counts as ADC.
     */
    static Property<String> resolveProjectId(GcpInterface gcpInterface, boolean fromExplicitServiceAccount, GoogleCredentials credentials) {
        if (gcpInterface.getProjectId() != null) {
            return gcpInterface.getProjectId();
        }
        if ((fromExplicitServiceAccount || gcpInterface.inferProjectIdFromApplicationDefault())
            && credentials instanceof ServiceAccountCredentials serviceAccountCredentials
            && serviceAccountCredentials.getProjectId() != null) {
            return Property.ofValue(serviceAccountCredentials.getProjectId());
        }
        return null;
    }
}
