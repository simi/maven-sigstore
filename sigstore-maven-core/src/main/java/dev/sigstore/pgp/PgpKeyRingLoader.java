package dev.sigstore.pgp;

import static dev.sigstore.pgp.PgpSupport.DEFAULT_PGP_KEYRING;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

public class PgpKeyRingLoader {

  public static void main(String[] args) throws Exception {
    new PgpKeyRingLoader().load();
  }

  public PGPSecretKey load() throws IOException {
    return load(DEFAULT_PGP_KEYRING, null);
  }

  public PGPSecretKey load(File keyRing) throws IOException {
    return load(keyRing, null);
  }

  public PGPSecretKey load(File keyRing, String id) throws IOException {
    if (!keyRing.exists()) {
      throw new IOException("No such key ring file exists: " + keyRing);
    }
    try (InputStream in = PGPUtil.getDecoderStream(new FileInputStream(keyRing))) {
      PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(in, new JcaKeyFingerprintCalculator());
      Object pgpObject;
      while ((pgpObject = pgpObjectFactory.nextObject()) != null) {
        if (!(pgpObject instanceof PGPSecretKeyRing)) {
          throw new IOException("Expecting a secret key but found " + pgpObject);
        }
        PGPSecretKeyRing key = (PGPSecretKeyRing) pgpObject;
        if (id == null) {
          // pick up the first one if no key ID specifier is given
          return key.getSecretKey();
        }
        Iterator<?> jtr = key.getSecretKeys();
        while (jtr.hasNext()) {
          PGPSecretKey secretKey = (PGPSecretKey) jtr.next();
          if (id.equalsIgnoreCase(Long.toHexString(secretKey.getPublicKey().getKeyID()))) {
            return secretKey;
          }
          for (Iterator<?> ktr = secretKey.getUserIDs(); ktr.hasNext(); ) {
            String s = (String) ktr.next();
            if (s.contains(id)) {
              return secretKey;
            }
          }
        }
      }
    }
    throw new IOException("no id: " + id);
  }
}
