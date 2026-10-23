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
import com.google.auth.oauth2.IdentityPoolCredentials;
import com.google.auth.oauth2.ImpersonatedCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;

import io.kestra.core.exceptions.IllegalVariableEvaluationException;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContext;
import io.kestra.core.serializers.JacksonMapper;

public final class CredentialService {
    static final String WORKLOAD_IDENTITY_TOKEN_URL = "https://sts.googleapis.com/v1/token";
    static final String WORKLOAD_IDENTITY_SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";

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
        GoogleCredentials sourceCredentials = renderNonBlank(runContext, gcpInterface.getWorkloadIdentityToken()).isPresent()
            ? workloadIdentityCredentials(runContext, gcpInterface, serviceAccount, scopes)
            : sourceCredentials(runContext, serviceAccount, scopes);
        Property<String> projectId = resolveProjectId(gcpInterface, serviceAccount.isPresent(), sourceCredentials);
        GoogleCredentials credentials = impersonate(runContext, gcpInterface, sourceCredentials, scopes);
        return new GcpConnection(credentials, projectId);
    }

    /**
     * Treats a blank render as unset, since expressions like {@code "{{ outputs.x.key | default(null) }}"} renders
     * to {@code ""} rather than {@code null} when {@code key} is missing.
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
     * Builds federated credentials from an OIDC token: Google STS exchanges it for an access token at first
     * use, so no key material is involved. The token property is rendered again, bypassing the property
     * cache, every time the SDK refreshes: a token minted by {@code oidcToken()} lives minutes while a task
     * may run for hours, so replaying the first one would fail the first refresh.
     */
    static GoogleCredentials workloadIdentityCredentials(RunContext runContext, GcpInterface gcpInterface, Optional<String> serviceAccount, List<String> scopes)
        throws IllegalVariableEvaluationException {
        if (serviceAccount.isPresent()) {
            throw new IllegalArgumentException("Set either serviceAccount or workloadIdentityToken, not both: they are two different ways to obtain the source identity.");
        }
        String audience = renderNonBlank(runContext, gcpInterface.getWorkloadIdentityAudience())
            .orElseThrow(() -> new IllegalArgumentException("workloadIdentityToken needs workloadIdentityAudience: the resource name of the workload identity pool provider the token was minted for."));

        IdentityPoolCredentials.Builder builder = IdentityPoolCredentials.newBuilder()
            .setAudience(audience)
            .setSubjectTokenType(WORKLOAD_IDENTITY_SUBJECT_TOKEN_TYPE)
            .setTokenUrl(WORKLOAD_IDENTITY_TOKEN_URL)
            .setSubjectTokenSupplier(context -> freshWorkloadIdentityToken(runContext, gcpInterface));
        if (!scopes.isEmpty()) {
            builder.setScopes(scopes);
        }
        runContext.logger().trace(" • Using workload identity federation with audience: {}", audience);
        return builder.build();
    }

    static String freshWorkloadIdentityToken(RunContext runContext, GcpInterface gcpInterface) throws IOException {
        try {
            return runContext.render(gcpInterface.getWorkloadIdentityToken()).skipCache().as(String.class)
                .filter(value -> !value.isBlank())
                .orElseThrow(() -> new IOException("workloadIdentityToken rendered to an empty value while refreshing the federated credentials."));
        } catch (IllegalVariableEvaluationException e) {
            throw new IOException("Cannot render workloadIdentityToken while refreshing the federated credentials: " + e.getMessage(), e);
        }
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
            renderNonBlank(runContext, gcpInterface.getImpersonatedServiceAccount())
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
