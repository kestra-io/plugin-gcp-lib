package io.kestra.plugin.gcp.shared;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.IdentityPoolCredentials;
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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@KestraTest
class CredentialServiceTest {

    private static final String CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform";
    private static final String BLANK_EXPRESSION = "{{ inputs.x | default(null) }}";
    private static final String ADC_PROJECT_ID = "adc-project";
    private static final String WIF_AUDIENCE = "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/k";
    private static final String ADC_CLIENT_EMAIL = "adc@adc-project.iam.gserviceaccount.com";

    @Inject
    private RunContextFactory runContextFactory;

    /**
     * Minimal, hermetic {@link GcpInterface} implementation used to drive the service under test.
     * Any accessor a given test does not exercise is simply passed {@code null}. {@code inferFromAdc}
     * models the plugin-gcp (true) vs plugin-ee-gcp (false) override of
     * {@link GcpInterface#inferProjectIdFromApplicationDefault()}.
     */
    private record WorkloadIdentityGcpInterface(
        Property<String> projectId,
        Property<String> serviceAccount,
        Property<String> impersonatedServiceAccount,
        Property<List<String>> scopes,
        Property<String> workloadIdentityToken,
        Property<String> workloadIdentityAudience
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

        @Override
        public Property<String> getWorkloadIdentityToken() {
            return workloadIdentityToken;
        }

        @Override
        public Property<String> getWorkloadIdentityAudience() {
            return workloadIdentityAudience;
        }
    }

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

        Property<String> resolved = CredentialService.resolveProjectId(gcpInterface, false, null);

        assertThat(resolved, is(gcpInterface.getProjectId()));
    }

    @Test
    void shouldFallBackToServiceAccountProjectIdWhenNotSet() throws Exception {
        GcpInterface gcpInterface = new TestGcpInterface(null, Property.ofValue("sa-key"), null, null);
        ServiceAccountCredentials credentials = serviceAccountCredentials("my-project");

        Property<String> resolved = CredentialService.resolveProjectId(gcpInterface, true, credentials);

        assertThat(resolved, is(Property.ofValue("my-project")));
    }

    @Test
    void shouldInferProjectIdFromAdcWhenAllowed() throws Exception {
        // serviceAccount unset, so credentials come from Application Default Credentials. plugin-gcp
        // (inferFromAdc = true) keeps its historical behaviour of adopting the key file's project id.
        GcpInterface gcpInterface = new TestGcpInterface(null, null, null, null, true);
        ServiceAccountCredentials adcCredentials = serviceAccountCredentials("host-key-project");

        Property<String> resolved = CredentialService.resolveProjectId(gcpInterface, false, adcCredentials);

        assertThat(resolved, is(Property.ofValue("host-key-project")));
    }

    @Test
    void shouldNotInferProjectIdFromAdcWhenGated() throws Exception {
        // plugin-ee-gcp (inferFromAdc = false) requires an explicit projectId in this case: the ADC
        // key file's project id must not be adopted silently.
        GcpInterface gcpInterface = new TestGcpInterface(null, null, null, null, false);
        ServiceAccountCredentials adcCredentials = serviceAccountCredentials("host-key-project");

        Property<String> resolved = CredentialService.resolveProjectId(gcpInterface, false, adcCredentials);

        assertThat(resolved, is(nullValue()));
    }

    @Test
    void shouldReturnNullWhenNoProjectIdAndNoServiceAccountCredentials() {
        GcpInterface gcpInterface = new TestGcpInterface(null, null, null, null);
        GoogleCredentials credentials = GoogleCredentials.newBuilder().build();

        Property<String> resolved = CredentialService.resolveProjectId(gcpInterface, false, credentials);

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
    void shouldBuildWorkloadIdentityCredentialsFromToken() throws Exception {
        RunContext runContext = runContextFactory.of();
        GcpInterface gcpInterface = new WorkloadIdentityGcpInterface(
            Property.ofValue("my-project"),
            null,
            null,
            Property.ofValue(List.of(CLOUD_PLATFORM_SCOPE)),
            Property.ofValue("eyJhbGciOiJSUzI1NiJ9.e30.sig"),
            Property.ofValue(WIF_AUDIENCE)
        );

        CredentialService.GcpConnection connection = CredentialService.connection(runContext, gcpInterface);

        assertThat(connection.credentials(), instanceOf(IdentityPoolCredentials.class));
        IdentityPoolCredentials credentials = (IdentityPoolCredentials) connection.credentials();
        assertThat(credentials.getAudience(), is(WIF_AUDIENCE));
        assertThat(credentials.getSubjectTokenType(), is(CredentialService.WORKLOAD_IDENTITY_SUBJECT_TOKEN_TYPE));
        assertThat(credentials.getTokenUrl(), is(CredentialService.WORKLOAD_IDENTITY_TOKEN_URL));
        assertThat(credentials.retrieveSubjectToken(), is("eyJhbGciOiJSUzI1NiJ9.e30.sig"));
        assertThat(credentials.getScopes(), hasItem(CLOUD_PLATFORM_SCOPE));
        assertThat(connection.projectId(), is(Property.ofValue("my-project")));
    }

    @Test
    void shouldRenderTheWorkloadIdentityTokenAgainOnEveryRefresh() throws Exception {
        // oidcToken() mints a short-lived token: replaying the first render on the SDK's hourly refresh would fail.
        RunContext runContext = runContextFactory.of();
        GcpInterface gcpInterface = new WorkloadIdentityGcpInterface(
            null, null, null, Property.ofValue(List.of()),
            Property.ofExpression("{{ now() }}"),
            Property.ofValue(WIF_AUDIENCE)
        );

        IdentityPoolCredentials credentials = (IdentityPoolCredentials) CredentialService.connection(runContext, gcpInterface).credentials();
        String first = credentials.retrieveSubjectToken();
        Thread.sleep(5);
        String second = credentials.retrieveSubjectToken();

        assertThat(first.equals(second), is(false));
    }

    @Test
    void shouldLayerImpersonationOnWorkloadIdentityCredentials() throws Exception {
        RunContext runContext = runContextFactory.of();
        GcpInterface gcpInterface = new WorkloadIdentityGcpInterface(
            null,
            null,
            Property.ofValue("target@my-project.iam.gserviceaccount.com"),
            Property.ofValue(List.of(CLOUD_PLATFORM_SCOPE)),
            Property.ofValue("eyJhbGciOiJSUzI1NiJ9.e30.sig"),
            Property.ofValue(WIF_AUDIENCE)
        );

        CredentialService.GcpConnection connection = CredentialService.connection(runContext, gcpInterface);

        assertThat(connection.credentials(), instanceOf(ImpersonatedCredentials.class));
        assertThat(((ImpersonatedCredentials) connection.credentials()).getSourceCredentials(), instanceOf(IdentityPoolCredentials.class));
        assertThat(connection.projectId(), nullValue());
    }

    @Test
    void shouldRejectWorkloadIdentityTokenWithoutAudienceOrWithServiceAccount() throws Exception {
        RunContext runContext = runContextFactory.of();
        GcpInterface noAudience = new WorkloadIdentityGcpInterface(null, null, null, Property.ofValue(List.of()), Property.ofValue("token"), null);
        GcpInterface withKey = new WorkloadIdentityGcpInterface(null, Property.ofValue(serviceAccountJson()), null, Property.ofValue(List.of()), Property.ofValue("token"), Property.ofValue(WIF_AUDIENCE));

        IllegalArgumentException missing = assertThrows(IllegalArgumentException.class, () -> CredentialService.connection(runContext, noAudience));
        assertThat(missing.getMessage().contains("workloadIdentityAudience"), is(true));
        IllegalArgumentException both = assertThrows(IllegalArgumentException.class, () -> CredentialService.connection(runContext, withKey));
        assertThat(both.getMessage().contains("not both"), is(true));
    }

    @Test
    void shouldTreatBlankRenderedValueAsUnset() throws Exception {
        // `{{ ... | default(null) }}` renders to "" rather than null (kestra-io/plugin-gcp#494).
        RunContext runContext = runContextFactory.of(Map.of("inputs", Map.of("blank", "  ")));

        assertThat(CredentialService.renderNonBlank(runContext, null), is(Optional.empty()));
        assertThat(CredentialService.renderNonBlank(runContext, Property.ofExpression("{{ null }}")), is(Optional.empty()));
        assertThat(CredentialService.renderNonBlank(runContext, Property.ofExpression("{{ inputs.missing | default(null) }}")), is(Optional.empty()));
        assertThat(CredentialService.renderNonBlank(runContext, Property.ofExpression("{{ inputs.blank }}")), is(Optional.empty()));
        assertThat(CredentialService.renderNonBlank(runContext, Property.ofValue("key")), is(Optional.of("key")));
    }

    @Test
    void shouldRejectBlankImpersonatedServiceAccount() throws Exception {
        // Unlike serviceAccount, a blank impersonation target must fail: dropping it would silently run
        // as the (usually broader) source identity.
        RunContext runContext = runContextFactory.of(Map.of("inputs", Map.of("blank", "  ")));
        GoogleCredentials sourceCredentials = serviceAccountCredentials("my-project");

        for (String expression : List.of("{{ inputs.missing | default(null) }}", "{{ inputs.blank }}")) {
            GcpInterface gcpInterface = new TestGcpInterface(null, null, Property.ofExpression(expression), null);

            IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> CredentialService.impersonate(runContext, gcpInterface, sourceCredentials, List.of())
            );
            assertThat(exception.getMessage(), is("impersonatedServiceAccount rendered to an empty value"));
        }
    }

    @Test
    void shouldImpersonateOnTopOfAdcWhenServiceAccountRendersBlank() throws Exception {
        writeAdcKey();
        RunContext runContext = runContextFactory.of(Map.of("inputs", Map.of()));
        GcpInterface gcpInterface = new TestGcpInterface(
            null,
            Property.ofExpression(BLANK_EXPRESSION),
            Property.ofValue("target@my-project.iam.gserviceaccount.com"),
            Property.ofValue(List.of(CLOUD_PLATFORM_SCOPE))
        );

        CredentialService.GcpConnection connection = CredentialService.connection(runContext, gcpInterface);

        // the source must be the ADC key, not a fromStream parse of the blank serviceAccount
        assertThat(connection.credentials(), instanceOf(ImpersonatedCredentials.class));
        GoogleCredentials source = ((ImpersonatedCredentials) connection.credentials()).getSourceCredentials();
        assertThat(source, instanceOf(ServiceAccountCredentials.class));
        assertThat(((ServiceAccountCredentials) source).getClientEmail(), is(ADC_CLIENT_EMAIL));
    }

    @Test
    void shouldNotInferProjectIdFromAdcWhenServiceAccountRendersBlankAndGated() throws Exception {
        writeAdcKey();
        RunContext runContext = runContextFactory.of(Map.of("inputs", Map.of()));
        GcpInterface gcpInterface = new TestGcpInterface(
            null,
            Property.ofExpression(BLANK_EXPRESSION),
            null,
            Property.ofValue(List.of(CLOUD_PLATFORM_SCOPE)),
            false
        );

        CredentialService.GcpConnection connection = CredentialService.connection(runContext, gcpInterface);

        // a configured-but-blank serviceAccount counts as ADC, so the gate applies
        assertThat(connection.projectId(), is(nullValue()));
    }

    @Test
    void shouldInferProjectIdFromAdcWhenServiceAccountRendersBlankAndAllowed() throws Exception {
        writeAdcKey();
        RunContext runContext = runContextFactory.of(Map.of("inputs", Map.of()));
        GcpInterface gcpInterface = new TestGcpInterface(
            null,
            Property.ofExpression(BLANK_EXPRESSION),
            null,
            Property.ofValue(List.of(CLOUD_PLATFORM_SCOPE)),
            true
        );

        CredentialService.GcpConnection connection = CredentialService.connection(runContext, gcpInterface);

        assertThat(connection.projectId(), is(Property.ofValue(ADC_PROJECT_ID)));
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
     * Writes a fake key where the Gradle test task points to {@code GOOGLE_APPLICATION_CREDENTIALS}.
     * Skips the test when run outside Gradle, since a JVM cannot set its own environment.
     */
    private static void writeAdcKey() throws Exception {
        String adcPath = System.getenv("GOOGLE_APPLICATION_CREDENTIALS");
        assumeTrue(adcPath != null && adcPath.endsWith("test-adc" + File.separator + "key.json"), "requires the Gradle test task's fake ADC");
        Path keyFile = Path.of(adcPath);
        Files.createDirectories(keyFile.getParent());
        Files.writeString(keyFile, serviceAccountJson(ADC_PROJECT_ID, ADC_CLIENT_EMAIL));
    }

    private static String serviceAccountJson() throws Exception {
        return serviceAccountJson("my-project", "test@my-project.iam.gserviceaccount.com");
    }

    /**
     * Builds a syntactically valid service-account JSON key with a freshly generated RSA private key.
     * Parsing it never touches the network: the key is only used for signing, not exchanged here.
     */
    private static String serviceAccountJson(String projectId, String clientEmail) throws Exception {
        String encodedKey = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
            .encodeToString(generateRsaKeyPair().getPrivate().getEncoded());
        String pem = "-----BEGIN PRIVATE KEY-----\n" + encodedKey + "\n-----END PRIVATE KEY-----\n";

        Map<String, Object> key = new LinkedHashMap<>();
        key.put("type", "service_account");
        key.put("project_id", projectId);
        key.put("private_key_id", "private-key-id");
        key.put("private_key", pem);
        key.put("client_email", clientEmail);
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
