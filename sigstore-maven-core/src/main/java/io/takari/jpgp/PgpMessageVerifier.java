package io.takari.jpgp;

import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;

public class PgpMessageVerifier extends PgpSupport {

  public boolean verifyMessage(InputStream publicKeyOfSender, InputStream message, InputStream signatureStream) {
    boolean result = false;
    try (InputStream armordPublicKeyStream = new ArmoredInputStream(signatureStream)) {
      Object pgpObject;
      PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(armordPublicKeyStream, new BcKeyFingerprintCalculator());
      while ((pgpObject = pgpObjectFactory.nextObject()) != null) {
        if (pgpObject instanceof PGPSignatureList) {
          PGPSignatureList signatureList = (PGPSignatureList) pgpObject;
          for (PGPSignature signature : signatureList) {
            PGPPublicKey pgpPublicKey = findPublicKey(publicKeyOfSender, pgpKey -> pgpKey.getKeyID() == signature.getKeyID());
            if (pgpPublicKey != null) {
              signature.init(new BcPGPContentVerifierBuilderProvider(), pgpPublicKey);
              IOUtils.process(message, signature::update);
              result = signature.verify();
            }
          }
        }
      }
    } catch (IOException | PGPException e) {
      result = false;
    }
    return result;
  }
}
