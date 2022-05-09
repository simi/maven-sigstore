package dev.sigstore.pgp;

import static org.junit.Assert.assertTrue;

import dev.sigstore.pgp.PgpKeyPairGenerator;
import dev.sigstore.pgp.PgpMessageSigner;
import dev.sigstore.pgp.PgpMessageVerifier;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.codehaus.plexus.util.FileUtils;
import org.junit.Test;

public class PGPSignAndVerifyRoundtripTest {

  String basedir;
  File sourceDirectory;
  File workingDirectory;

  @Test
  public void validateRoundtrip() throws Exception {
    basedir = System.getProperty("basedir", new File("").getAbsolutePath());
    sourceDirectory = new File(basedir, "src/test/files/roundtrip");
    workingDirectory = new File(basedir, "target/files/roundtrip");
    FileUtils.copyDirectory(sourceDirectory, workingDirectory);

    String user = "userid";
    String passphrase = "password";
    String privateKeyName = "private.asc";
    String publicKeyName = "public.asc";
    String messageName = "artifact.txt";
    String messageNameSignature = messageName + ".asc";

    // Generate a key pair for signing
    PgpKeyPairGenerator generator = new PgpKeyPairGenerator();
    try (
        OutputStream publicKeyStream = outputStream(publicKeyName);
        OutputStream privateKeyStream = outputStream(privateKeyName)) {
      PGPKeyPair keypair = generator.generateKeyPair(512);
      generator.exportPrivateKey(privateKeyStream, keypair, user, passphrase);
      generator.exportPublicKey(publicKeyStream, keypair);
    }

    // TODO: use the artifact signer in the test
    //PgpArtifactSigner artifactSigner = new PgpArtifactSigner();
    //artifactSigner.sign(file(messageName));

    // Sign the artifact
    PgpMessageSigner signer = new PgpMessageSigner();
    try (
        InputStream privateKeyInputStream = inputStream(privateKeyName);
        InputStream message = inputStream(messageName);
        OutputStream signatureOutputStream = outputStream(messageNameSignature)) {
      assertTrue(signer.signMessage(privateKeyInputStream, user, passphrase, message, signatureOutputStream));
    }

    // Verify the signature of the artifact
    PgpMessageVerifier verifier = new PgpMessageVerifier();
    try (
        InputStream publicKeyInputStream = inputStream(publicKeyName);
        InputStream message = inputStream(messageName);
        InputStream signatureInputStream = inputStream(messageNameSignature)) {
      assertTrue(verifier.verifyMessage(publicKeyInputStream, message, signatureInputStream));
    }
  }

  private InputStream inputStream(String name) throws IOException {
    return new FileInputStream(file(name));
  }

  private OutputStream outputStream(String name) throws IOException {
    return new FileOutputStream(file(name));
  }

  private File file(String name) {
    return new File(workingDirectory, name);
  }
}
