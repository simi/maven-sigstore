package io.takari.jpgp;

import static org.codehaus.plexus.util.FileUtils.copyDirectoryStructure;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.junit.Test;

public class GnupgSigningTest {

  String basedir;
  File sourceDirectory;
  File workingDirectory;

  @Test
  public void validateGnupgSigning() throws Exception {
    basedir = System.getProperty("basedir", new File("").getAbsolutePath());
    sourceDirectory = new File(basedir, "src/test/files/gnupg");
    workingDirectory = new File(basedir, "target/files/gnupg");
    copyDirectoryStructure(sourceDirectory, workingDirectory);

    PgpKeyRingLoader loader = new PgpKeyRingLoader();
    PGPSecretKey secretKey = loader.load(file("secring.gpg"));
    PgpMessageSigner signer = new PgpMessageSigner();
    InputStream message = inputStream("artifact-1.0.jar");
    OutputStream signature = outputStream("artifact-1.0.jar.asc");
    signer.signMessage(secretKey, "samuel", message, signature);
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
