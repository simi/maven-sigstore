package dev.sigstore.pgp;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.Before;
import org.junit.Test;

public class AsciiArmorExporterTest extends TestSupport {

  File workingDirectory;

  @Before
  public void setUp() {
    super.setUp();
    workingDirectory = files("armor");
  }

  @Test
  public void validateRoundtrip() throws Exception {
    String privateKeyName = "bob-from-keypair.asc";
    PgpKeyPairGenerator generator = new PgpKeyPairGenerator();
    PGPKeyPair keyPair  = new PgpKeyPairGenerator().generateKeyPair(512);
    try (
        OutputStream privateKeyStream = outputStream(privateKeyName)) {
      generator.exportPrivateKey(privateKeyStream, keyPair, "bob", "bob");
    }
  }

  @Test
  public void armorIsValidExportedFromSecretKeyRing() throws Exception {
    String privateKeyName = "bob-from-keyring.asc";
    PgpKeyPairGenerator generator = new PgpKeyPairGenerator();
    PGPSecretKeyRing keyRing  = generator.secretKeyRing("bob", "bob");
    try (
        OutputStream privateKeyStream = outputStream(privateKeyName)) {
      generator.exportKeyRing(privateKeyStream, keyRing);
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
