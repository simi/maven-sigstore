package dev.sigstore.plugin;

import static java.nio.file.Paths.get;
import static org.apache.maven.sigstore.model.rekord.Signature.Format.*;

import java.util.UUID;

public class Main {
  public static void main(String[] args) throws Exception {
    SigstoreRequest request = ImmutableSigstoreRequest.builder()
        .type(X_509)
        .emailAddress("jason@vanzyl.ca")
        .artifact(get("pom.xml"))
        //.artifact(get("/Users/jvanzyl/js/provisio/maven-sigstore-site/maven-sigstore-plugin-0.0.1-SNAPSHOT.jar"))
        //.artifact( Paths.get( "/Users/jvanzyl/.ssh/config" ) )
        //.artifact( Paths.get( "/Users/jvanzyl/js/provisio/maven-sigstore-site/hello.txt" ) )
        //.sshRequest(ImmutableSshRequest.builder()
            //.privateKey(get("/Users/jvanzyl/js/security/jssh/roundtrip0/id_ed25519"))
            //.publicKey(get("/Users/jvanzyl/js/security/jssh/roundtrip0/id_ed25519.pub")).build())
        .build();

    Sign signer = new Sign(request);
    signer.executeSigstoreFlow();
  }
}
