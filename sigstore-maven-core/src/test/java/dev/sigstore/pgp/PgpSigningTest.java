package dev.sigstore.pgp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.codehaus.plexus.util.FileUtils.copyDirectoryStructure;
import static org.junit.Assert.assertTrue;

import dev.sigstore.pgp.support.PgpArtifactSigner;
import dev.sigstore.pgp.support.PgpKeyPairGenerator;
import dev.sigstore.pgp.support.key.PgpKeyRingLoader;
import dev.sigstore.pgp.support.PgpMessageVerifier;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.codehaus.plexus.util.FileUtils;
import org.junit.Before;
import org.junit.Test;

public class PgpSigningTest {

  protected String basedir;
  protected File sourceDirectory;
  protected File workingDirectory;

  @Before
  public void setUp() {
    basedir = System.getProperty("basedir", new File("").getAbsolutePath());
  }

  @Test
  public void validateGnupgSigning() throws Exception {
    basedir = System.getProperty("basedir", new File("").getAbsolutePath());
    sourceDirectory = new File(basedir, "src/test/files/gnupg");
    workingDirectory = new File(basedir, "target/files/gnupg");
    copyDirectoryStructure(sourceDirectory, workingDirectory);

    PgpKeyRingLoader loader = new PgpKeyRingLoader();
    PGPSecretKey secretKey = loader.load(file("secring.gpg"));
    PgpArtifactSigner signer = new PgpArtifactSigner();
    InputStream message = inputStream("artifact-1.0.jar");
    OutputStream signature = outputStream("artifact-1.0.jar.asc");
    assertThat(signer.signMessage(secretKey, "samuel", message, signature)).isTrue();
  }

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


    // Sign the artifact
    PgpArtifactSigner signer = new PgpArtifactSigner();
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

  protected InputStream inputStream(String name) throws IOException {
    return new FileInputStream(file(name));
  }

  protected OutputStream outputStream(String name) throws IOException {
    return new FileOutputStream(file(name));
  }

  protected File file(String name) {
    return new File(workingDirectory, name);
  }
}
