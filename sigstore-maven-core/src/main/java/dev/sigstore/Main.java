package dev.sigstore;

import static dev.sigstore.SigstoreRequest.Type.X_509;
import static java.nio.file.Paths.get;

public class Main {

  public static void main(String[] args) throws Exception {
    new Main().execute();
  }

  private void execute() throws Exception {
    SigstoreRequest request = ImmutableSigstoreRequest.builder()
        .type(X_509)
        .emailAddress("jason@vanzyl.ca")
        .artifact(get("pom.xml"))
        .build();
    SigstoreSigner signer = new SigstoreSigner(request);
    signer.sign();
  }
}
