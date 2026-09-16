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
     * Any accessor a given test does not exercise is simply passed {@code null}. {@code inferFromAdc}
     * models the plugin-gcp (true) vs plugin-ee-gcp (false) override of
     * {@link GcpInterface#inferProjectIdFromApplicationDefault()}.
     */
    private record TestGcpInterface(
        Property<String> projectId,
        Property<String> serviceAccount,
        Property<String> impersonatedServiceAccount,
        Property<List<String>> scopes,
        boolean inferFromAdc
    ) implements GcpInterface {
        private TestGcpInterface(
            Property<String> projectId,
            Property<String> serviceAccount,
            Property<String> impersonatedServiceAccount,
            Property<List<String>> scopes
        ) {
            this(projectId, serviceAccount, impersonatedServiceAccount, scopes, true);
        }

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

        @Override
        public boolean inferProjectIdFromApplicationDefault() {
            return inferFromAdc;
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
    void shouldInferProjectIdFromAdcWhenAllowed() throws Exception {
        // serviceAccount unset, so credentials come from Application Default Credentials. plugin-gcp
        // (inferFromAdc = true) keeps its historical behaviour of adopting the key file's project id.
        GcpInterface gcpInterface = new TestGcpInterface(null, null, null, null, true);
        ServiceAccountCredentials adcCredentials = serviceAccountCredentials("host-key-project");

        Property<String> resolved = CredentialService.resolveProjectId(gcpInterface, adcCredentials);

        assertThat(resolved, is(Property.ofValue("host-key-project")));
    }

    @Test
    void shouldNotInferProjectIdFromAdcWhenGated() throws Exception {
        // plugin-ee-gcp (inferFromAdc = false) requires an explicit projectId in this case: the ADC
        // key file's project id must not be adopted silently.
        GcpInterface gcpInterface = new TestGcpInterface(null, null, null, null, false);
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
    void shouldBuildScopedServiceAccountCredentials() throws Exception {
        RunContext runContext = runContextFactory.of();
        GcpInterface gcpInterface = new TestGcpInterface(
            null,
            Property.ofValue(serviceAccountJson()),
            null,
            Property.ofValue(List.of(CLOUD_PLATFORM_SCOPE))
        );

        CredentialService.GcpConnection connection = CredentialService.connection(runContext, gcpInterface);

        assertThat(connection.credentials(), instanceOf(ServiceAccountCredentials.class));
        ServiceAccountCredentials serviceAccountCredentials = (ServiceAccountCredentials) connection.credentials();
        assertThat(serviceAccountCredentials.getClientEmail(), is("test@my-project.iam.gserviceaccount.com"));
        assertThat(serviceAccountCredentials.getScopes(), hasItem(CLOUD_PLATFORM_SCOPE));
        assertThat(connection.projectId(), is(Property.ofValue("my-project")));
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

        CredentialService.GcpConnection connection = CredentialService.connection(runContext, gcpInterface);

        assertThat(connection.credentials(), instanceOf(ImpersonatedCredentials.class));
        assertThat(((ImpersonatedCredentials) connection.credentials()).getAccount(), is("target@my-project.iam.gserviceaccount.com"));
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

        CredentialService.GcpConnection connection = CredentialService.connection(runContext, gcpInterface);

        // the final credentials are impersonated and carry no project id of their own, yet the
        // connection still exposes the project id read from the pre-impersonation source credentials.
        assertThat(connection.credentials(), instanceOf(ImpersonatedCredentials.class));
        assertThat(connection.projectId(), is(Property.ofValue("my-project")));
    }

    @Test
    void abstractTaskShouldExposeProjectIdUnderImpersonation() throws Exception {
        RunContext runContext = runContextFactory.of();
        // Locals are named to avoid clashing with the inherited protected fields: inside the
        // anonymous class an unqualified name resolves to the (still null) field, not the local.
        Property<String> serviceAccountKey = Property.ofValue(serviceAccountJson());
        Property<String> impersonated = Property.ofValue("target@my-project.iam.gserviceaccount.com");
        Property<List<String>> configuredScopes = Property.ofValue(List.of(CLOUD_PLATFORM_SCOPE));
        // Anonymous subclass on purpose: a named concrete AbstractTask would be picked up by the
        // Kestra plugin processor and registered as a plugin, which flips the test context into
        // plugin-registry mode and breaks storage discovery. Fields are protected, so we set them
        // directly rather than via the SuperBuilder.
        AbstractTask task = new AbstractTask() {
            {
                this.serviceAccount = serviceAccountKey;
                this.impersonatedServiceAccount = impersonated;
                this.scopes = configuredScopes;
            }
        };

        GoogleCredentials credentials = task.credentials(runContext);

        assertThat(credentials, instanceOf(ImpersonatedCredentials.class));
        assertThat(task.getProjectId(), is(Property.ofValue("my-project")));
    }

    /**
     * Builds a syntactically valid service-account JSON key with a freshly generated RSA private key.
     * Parsing it never touches the network: the key is only used for signing, not exchanged here.
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
