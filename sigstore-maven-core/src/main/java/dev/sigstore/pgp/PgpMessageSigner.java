package dev.sigstore.pgp;

import static dev.sigstore.pgp.IOUtils.process;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;

public class PgpMessageSigner extends PgpSupport {

  public boolean signMessage(InputStream privateKeyOfSender, final String userIdForPrivateKey, String passwordOfPrivateKey, InputStream message, OutputStream signature) {
    try {
      PGPPrivateKey privateKey = findPrivateKey(privateKeyOfSender, passwordOfPrivateKey, secretKey -> {
        boolean result = secretKey.isSigningKey();
        if (result) {
          Iterator<String> userIdIterator = secretKey.getUserIDs();
          boolean containsUserId = false;
          while (userIdIterator.hasNext() && !containsUserId) {
            containsUserId = userIdForPrivateKey.equals(userIdIterator.next());
          }
        }
        return result;
      });
      return signatureGenerator(message, signature, privateKey);
    } catch (IOException | PGPException e) {
      return false;
    }
  }

  public boolean signMessage(PGPSecretKey secretKey, String passwordOfPrivateKey, InputStream message, OutputStream signature) throws PGPException, IOException {
    PGPPrivateKey privateKey = findPrivateKey(secretKey, passwordOfPrivateKey);
    return signatureGenerator(message, signature, privateKey);
  }

  private boolean signatureGenerator(InputStream message, OutputStream signature, PGPPrivateKey privateKey) throws PGPException, IOException {
    final PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(privateKey.getPublicKeyPacket().getAlgorithm(), HashAlgorithmTags.SHA256));
    signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
    try (BCPGOutputStream outputStream = new BCPGOutputStream(new ArmoredOutputStream(signature))) {
      process(message, signatureGenerator::update);
      signatureGenerator.generate().encode(outputStream);
    }
    return true;
  }
}
