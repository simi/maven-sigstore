package dev.sigstore;

import static org.apache.maven.sigstore.model.rekord.Signature.Format.X_509;

import dev.sigstore.plugin.ImmutableSigstoreRequest;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.Test;

public class MainTest {

  @Test
  public void validateExecutionInGitHubActions() throws Exception {
    String basedir = new File("").getAbsolutePath();
    System.out.println("basedir = " + basedir);
    Path artifact = Paths.get(basedir, "pom.xml");
    SigstoreRequest request = ImmutableSigstoreRequest.builder()
        .type(X_509)
        .emailAddress("jason@vanzyl.ca")
        .artifact(artifact)
        .build();
    SigstoreSigner signer = new SigstoreSigner(request);
    signer.executeSigstoreFlow();
  }
}
