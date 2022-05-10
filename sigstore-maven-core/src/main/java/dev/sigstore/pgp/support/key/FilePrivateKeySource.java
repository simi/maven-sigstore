package dev.sigstore.pgp.support.key;

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

import static org.bouncycastle.openpgp.PGPUtil.getDecoderStream;

import java.io.FileInputStream;
import java.io.IOException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

public class FilePrivateKeySource {
  public PGPSecretKey load(String keyFile) throws IOException {
    try (FileInputStream inputStream = new FileInputStream(keyFile)) {
      PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(getDecoderStream(inputStream), new JcaKeyFingerprintCalculator());
      Object pgpObject = pgpObjectFactory.nextObject();
      if (!(pgpObject instanceof PGPSecretKeyRing)) {
        throw new IOException(keyFile + " doesn't contain PGP private key");
      }
      PGPSecretKeyRing keyRing = (PGPSecretKeyRing) pgpObject;
      return keyRing.getSecretKey();
    }
  }
}
