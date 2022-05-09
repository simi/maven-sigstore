package dev.sigstore.pgp.passphrase;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import org.bouncycastle.openpgp.PGPSecretKey;

public class FilePassphraseSource implements PassphraseSource {

  private File file;

  public FilePassphraseSource(File file) {
    this.file = file;
  }

  public String load(PGPSecretKey secretKey) throws IOException {
    if (!file.exists()) {
      return null;
    }
    return new String(Files.readAllBytes(file.toPath())).trim();
  }
}
