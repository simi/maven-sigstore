package dev.sigstore.pgp;

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

import static dev.sigstore.pgp.PgpSupport.DEFAULT_PGP_KEYRING;
import static dev.sigstore.pgp.PgpSupport.jpgpPassphraseFile;

import dev.sigstore.pgp.passphrase.FilePassphraseSource;
import dev.sigstore.pgp.passphrase.GpgAgentPassphraseSource;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PgpArtifactSigner {

  private static final Logger logger = LoggerFactory.getLogger(PgpArtifactSigner.class);

  private final PGPSecretKey secretKey;
  private final PgpMessageSigner signer;

  public PgpArtifactSigner() throws IOException {
    secretKey = new PgpKeyRingLoader().load(DEFAULT_PGP_KEYRING);
    signer = new PgpMessageSigner();
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
      signer.signMessage(secretKey, passphrase, inputStream, outputStream);
    }
    return signatureFile;
  }

  public String signToString(File fileToSign) throws IOException, PGPException {
    return signToString(fileToSign, findPassphrase());
  }

  public String signToString(File fileToSign, String passphrase) throws IOException, PGPException {
    try (InputStream inputStream = new FileInputStream(fileToSign); ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
      signer.signMessage(secretKey, passphrase, inputStream, baos);
      return baos.toString();
    }
  }

  private String findPassphrase() throws IOException {

    logger.info("No passphrase provided so searching with configured loaders:");

    logger.info("Looking for envar PGP_PASSPHRASE for passphrase.");
    String passphrase = System.getenv("PGP_PASSPHRASE");
    if (passphrase != null) {
      logger.info("Found passphrase in envar PGP_PASSPHRASE.");
      return passphrase;
    }

    logger.info("Looking in ~/.gnupg/.jpgp.passphrase for passphrase.");
    passphrase = new FilePassphraseSource(jpgpPassphraseFile).load(secretKey);
    if (passphrase != null) {
      logger.info("Found passphrase ~/.gnupg/.jpgp.passphrase");
      return passphrase;
    }

    logger.info("Asking pgp agent for passphrase.");
    passphrase = new GpgAgentPassphraseSource().load(secretKey);
    // The only way to know if the passphrase is correct is to attempt using it. We'll
    // allow 5 retries as that should account for any mistakes adequately. Or does the agent...
    if (passphrase != null) {
      logger.info("Found passphrase from gpg agent.");
      return passphrase;
    }

    return passphrase;
  }
}
