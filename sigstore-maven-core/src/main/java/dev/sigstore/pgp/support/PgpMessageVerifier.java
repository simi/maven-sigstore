package dev.sigstore.pgp.support;

//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

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
