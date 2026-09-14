package io.kestra.plugin.gcp.shared;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;

import io.kestra.core.models.property.Property;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

class CredentialServiceTest {

    /**
     * Minimal, hermetic {@link GcpInterface} implementation: only {@code projectId} is ever set by
     * these tests, the other accessors are irrelevant to {@code resolveProjectId} and are never
     * invoked, but must be implemented to satisfy the interface.
     */
    private record TestGcpInterface(Property<String> projectId) implements GcpInterface {
        @Override
        public Property<String> getProjectId() {
            return projectId;
        }

        @Override
        public Property<String> getServiceAccount() {
            return null;
        }

        @Override
        public Property<String> getImpersonatedServiceAccount() {
            return null;
        }

        @Override
        public Property<List<String>> getScopes() {
            return null;
        }
    }

    @Test
    void shouldReturnExplicitProjectIdWhenSet() {
        GcpInterface gcpInterface = new TestGcpInterface(Property.ofValue("explicit-project"));

        Property<String> resolved = CredentialService.resolveProjectId(gcpInterface, null);

        assertThat(resolved, is(gcpInterface.getProjectId()));
    }

    @Test
    void shouldFallBackToServiceAccountProjectIdWhenNotSet() throws NoSuchAlgorithmException {
        GcpInterface gcpInterface = new TestGcpInterface(null);
        ServiceAccountCredentials credentials = ServiceAccountCredentials.newBuilder()
            .setClientId("client-id")
            .setClientEmail("test@my-project.iam.gserviceaccount.com")
            .setPrivateKey(generateRsaKeyPair().getPrivate())
            .setPrivateKeyId("private-key-id")
            .setProjectId("my-project")
            .build();

        Property<String> resolved = CredentialService.resolveProjectId(gcpInterface, credentials);

        assertThat(resolved, is(Property.ofValue("my-project")));
    }

    @Test
    void shouldReturnNullWhenNoProjectIdAndNoServiceAccountCredentials() {
        GcpInterface gcpInterface = new TestGcpInterface(null);
        GoogleCredentials credentials = GoogleCredentials.newBuilder().build();

        Property<String> resolved = CredentialService.resolveProjectId(gcpInterface, credentials);

        assertThat(resolved, is(nullValue()));
    }

    private static KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }
}
