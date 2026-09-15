package io.kestra.plugin.gcp.shared;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import com.google.auth.oauth2.GoogleCredentials;

import io.kestra.core.exceptions.IllegalVariableEvaluationException;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.Task;
import io.kestra.core.runners.RunContext;

import lombok.*;
import lombok.experimental.SuperBuilder;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
public abstract class AbstractTask extends Task implements GcpInterface {
    protected Property<String> projectId;

    @ToString.Exclude
    protected Property<String> serviceAccount;

    @ToString.Exclude
    protected Property<String> impersonatedServiceAccount;

    @Builder.Default
    protected Property<List<String>> scopes = Property.ofValue(Collections.singletonList("https://www.googleapis.com/auth/cloud-platform"));

    public GoogleCredentials credentials(RunContext runContext) throws IllegalVariableEvaluationException, IOException {
        CredentialService.GcpConnection connection = CredentialService.connection(runContext, this);
        // Preserved from plugin-gcp: concrete tasks (and gcs.Trigger) read getProjectId() after this
        // call, so the resolved project id is written back onto the configured property.
        this.projectId = connection.projectId();
        return connection.credentials();
    }
}
