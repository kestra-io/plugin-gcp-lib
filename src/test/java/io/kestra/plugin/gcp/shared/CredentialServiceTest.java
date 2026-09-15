package io.kestra.plugin.gcp.shared;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ImpersonatedCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;

import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContext;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.serializers.JacksonMapper;

import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

@KestraTest
class CredentialServiceTest {

    private static final String CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform";

    @Inject
    private RunContextFactory runContextFactory;

    /**
     * Minimal, hermetic {@link GcpInterface} implementation used to drive the service under test.
     * Any accessor a given test does not exercise is simply passed {@code null}.
     */
    private record TestGcpInterface(
        Property<String> projectId,
        Property<String> serviceAccount,
        Property<String> impersonatedServiceAccount,
        Property<List<String>> scopes
    ) implements GcpInterface {
        @Override
        public Property<String> getProjectId() {
            return projectId;
        }

        @Override
        public Property<String> getServiceAccount() {
            return serviceAccount;
        }

        @Override
        public Property<String> getImpersonatedServiceAccount() {
            return impersonatedServiceAccount;
        }

        @Override
        public Property<List<String>> getScopes() {
            return scopes;
        }
    }

    @Test
    void shouldReturnExplicitProjectIdWhenSet() {
        GcpInterface gcpInterface = new TestGcpInterface(Property.ofValue("explicit-project"), null, null, null);

        Property<String> resolved = CredentialService.resolveProjectId(gcpInterface, null);

        assertThat(resolved, is(gcpInterface.getProjectId()));
    }

    @Test
    void shouldFallBackToServiceAccountProjectIdWhenNotSet() throws Exception {
        GcpInterface gcpInterface = new TestGcpInterface(null, Property.ofValue("sa-key"), null, null);
        ServiceAccountCredentials credentials = serviceAccountCredentials("my-project");

        Property<String> resolved = CredentialService.resolveProjectId(gcpInterface, credentials);

        assertThat(resolved, is(Property.ofValue("my-project")));
    }

    @Test
    void shouldNotInferProjectIdFromAdcWhenServiceAccountUnset() throws Exception {
        // serviceAccount unset: credentials come from Application Default Credentials. Even when ADC
        // resolves to a service-account key (GOOGLE_APPLICATION_CREDENTIALS), its project id must not
        // be adopted silently — the run keeps failing explicitly downstream, as it did before.
        GcpInterface gcpInterface = new TestGcpInterface(null, null, null, null);
        ServiceAccountCredentials adcCredentials = serviceAccountCredentials("host-key-project");

        Property<String> resolved = CredentialService.resolveProjectId(gcpInterface, adcCredentials);

        assertThat(resolved, is(nullValue()));
    }

    @Test
    void shouldReturnNullWhenNoProjectIdAndNoServiceAccountCredentials() {
        GcpInterface gcpInterface = new TestGcpInterface(null, null, null, null);
        GoogleCredentials credentials = GoogleCredentials.newBuilder().build();

        Property<String> resolved = CredentialService.resolveProjectId(gcpInterface, credentials);

        assertThat(resolved, is(nullValue()));
    }

    @Test
    void shouldBuildScopedServiceAccountCredentialsFromJsonKey() throws Exception {
        RunContext runContext = runContextFactory.of();
        GcpInterface gcpInterface = new TestGcpInterface(
            null,
            Property.ofValue(serviceAccountJson()),
            null,
            Property.ofValue(List.of(CLOUD_PLATFORM_SCOPE))
        );

        GoogleCredentials credentials = CredentialService.credentials(runContext, gcpInterface);

        assertThat(credentials, instanceOf(ServiceAccountCredentials.class));
        ServiceAccountCredentials serviceAccountCredentials = (ServiceAccountCredentials) credentials;
        assertThat(serviceAccountCredentials.getClientEmail(), is("test@my-project.iam.gserviceaccount.com"));
        assertThat(serviceAccountCredentials.getScopes(), hasItem(CLOUD_PLATFORM_SCOPE));
    }

    @Test
    void shouldWrapCredentialsWithImpersonationWhenRequested() throws Exception {
        RunContext runContext = runContextFactory.of();
        GcpInterface gcpInterface = new TestGcpInterface(
            null,
            Property.ofValue(serviceAccountJson()),
            Property.ofValue("target@my-project.iam.gserviceaccount.com"),
            Property.ofValue(List.of(CLOUD_PLATFORM_SCOPE))
        );

        GoogleCredentials credentials = CredentialService.credentials(runContext, gcpInterface);

        assertThat(credentials, instanceOf(ImpersonatedCredentials.class));
        assertThat(((ImpersonatedCredentials) credentials).getAccount(), is("target@my-project.iam.gserviceaccount.com"));
    }

    @Test
    void shouldResolveProjectIdFromSourceCredentialsWhenImpersonated() throws Exception {
        RunContext runContext = runContextFactory.of();
        GcpInterface gcpInterface = new TestGcpInterface(
            null,
            Property.ofValue(serviceAccountJson()),
            Property.ofValue("target@my-project.iam.gserviceaccount.com"),
            Property.ofValue(List.of(CLOUD_PLATFORM_SCOPE))
        );

        GoogleCredentials sourceCredentials = CredentialService.sourceCredentials(runContext, gcpInterface);
        GoogleCredentials credentials = CredentialService.credentials(runContext, gcpInterface);

        // the final credentials are impersonated and carry no project id of their own
        assertThat(credentials, instanceOf(ImpersonatedCredentials.class));

        // project id must be resolved from the pre-impersonation source credentials, not the wrapper
        Property<String> resolvedProjectId = CredentialService.resolveProjectId(gcpInterface, sourceCredentials);
        assertThat(resolvedProjectId, is(Property.ofValue("my-project")));
    }

    /**
     * Builds a syntactically valid service-account JSON key with a freshly generated RSA private key.
     * Parsing it never touches the network — the key is only used for signing, not exchanged here.
     */
    private static String serviceAccountJson() throws Exception {
        String encodedKey = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
            .encodeToString(generateRsaKeyPair().getPrivate().getEncoded());
        String pem = "-----BEGIN PRIVATE KEY-----\n" + encodedKey + "\n-----END PRIVATE KEY-----\n";

        Map<String, Object> key = new LinkedHashMap<>();
        key.put("type", "service_account");
        key.put("project_id", "my-project");
        key.put("private_key_id", "private-key-id");
        key.put("private_key", pem);
        key.put("client_email", "test@my-project.iam.gserviceaccount.com");
        key.put("client_id", "client-id");
        key.put("token_uri", "https://oauth2.googleapis.com/token");

        return JacksonMapper.ofJson().writeValueAsString(key);
    }

    private static ServiceAccountCredentials serviceAccountCredentials(String projectId) throws Exception {
        return ServiceAccountCredentials.newBuilder()
            .setClientId("client-id")
            .setClientEmail("test@" + projectId + ".iam.gserviceaccount.com")
            .setPrivateKey(generateRsaKeyPair().getPrivate())
            .setPrivateKeyId("private-key-id")
            .setProjectId(projectId)
            .build();
    }

    private static KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }
}
