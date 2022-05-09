package dev.sigstore.pgp.key;

import java.io.FileInputStream;
import java.io.IOException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

/**
 * Loads PGP secret key from the exported key file, which normally ends with the ".asc" extension and has a "-----BEGIN PGP PRIVATE KEY BLOCK-----" header.
 *
 * @author Kohsuke Kawaguchi
 */
public class FilePrivateKeySource {

  public PGPSecretKey load(String keyFile) throws IOException {
    try (FileInputStream inputStream = new FileInputStream(keyFile)) {
      PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(PGPUtil.getDecoderStream(inputStream), new JcaKeyFingerprintCalculator());
      Object pgpObject = pgpObjectFactory.nextObject();
      if (!(pgpObject instanceof PGPSecretKeyRing)) {
        throw new IOException(keyFile + " doesn't contain PGP private key");
      }
      PGPSecretKeyRing keyRing = (PGPSecretKeyRing) pgpObject;
      return keyRing.getSecretKey();
    }
  }
}
