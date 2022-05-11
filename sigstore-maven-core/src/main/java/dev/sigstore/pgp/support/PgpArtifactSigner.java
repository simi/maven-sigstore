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

import static dev.sigstore.pgp.support.IOUtils.process;

import dev.sigstore.pgp.support.key.PgpKeyRingLoader;
import dev.sigstore.pgp.support.passphrase.FilePassphraseSource;
import dev.sigstore.pgp.support.passphrase.GpgAgentPassphraseSource;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PgpArtifactSigner extends PgpSupport {

  private static final Logger logger = LoggerFactory.getLogger(PgpArtifactSigner.class);

  private final PGPSecretKey secretKey;

  public PgpArtifactSigner() throws IOException {
    secretKey = new PgpKeyRingLoader().load(DEFAULT_PGP_KEYRING);
  }

  public File sign(File fileToSign) throws IOException, PGPException {
    return sign(fileToSign, findPassphrase());
  }

  public File sign(File fileToSign, String passphrase) throws IOException, PGPException {
    if (passphrase == null) {
      passphrase = findPassphrase();
    }
    File signatureFile = new File(fileToSign.getParentFile(), fileToSign.getName() + ".asc");
    try (InputStream inputStream = new FileInputStream(fileToSign); OutputStream outputStream = new FileOutputStream(signatureFile)) {
      signMessage(secretKey, passphrase, inputStream, outputStream);
    }
    return signatureFile;
  }

  public String signToString(File fileToSign) throws IOException, PGPException {
    return signToString(fileToSign, findPassphrase());
  }

  public String signToString(File fileToSign, String passphrase) throws IOException, PGPException {
    try (InputStream inputStream = new FileInputStream(fileToSign); ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
      signMessage(secretKey, passphrase, inputStream, baos);
      return baos.toString();
    }
  }

  private String findPassphrase() throws IOException {
    String passphrase = System.getenv("PGP_PASSPHRASE");
    if (passphrase != null) {
      logger.info("Found passphrase in envar PGP_PASSPHRASE.");
      return passphrase;
    }

    passphrase = new FilePassphraseSource(jpgpPassphraseFile).load(secretKey);
    if (passphrase != null) {
      logger.info("Found passphrase ~/.gnupg/.jpgp.passphrase");
      return passphrase;
    }

    passphrase = new GpgAgentPassphraseSource().load(secretKey);
    if (passphrase != null) {
      logger.info("Found passphrase from gpg agent.");
      return passphrase;
    }

    return passphrase;
  }

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
