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

import static dev.sigstore.SigstoreSigner.base64;
import static dev.sigstore.SigstoreSigner.sha256;
import static java.nio.file.Files.writeString;

import dev.sigstore.ImmutableSigstoreResult;
import dev.sigstore.ImmutableSigstoreResult.Builder;
import dev.sigstore.SigstoreProcessorSupport;
import dev.sigstore.SigstoreRequest;
import dev.sigstore.SigstoreResult;
import dev.sigstore.pgp.support.PgpArtifactSigner;
import dev.sigstore.pgp.support.PgpKeyRingLoader;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Map;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

public class PgpProcessor extends SigstoreProcessorSupport {

  @Override
  public SigstoreResult process(SigstoreRequest request) throws Exception {
    Builder resultBuilder = ImmutableSigstoreResult.builder();

    Path artifact = request.artifact();
    //
    // base64 content of artifact
    // sha256 hash of artifact
    // base64 of public key
    // base64 of signature
    //
    Path sha256Path = artifact.resolveSibling(artifact.getFileName() + ".sha256");
    String sha256 = sha256(artifact);
    writeString(sha256Path, sha256);

    PgpKeyRingLoader kingRingLoader = new PgpKeyRingLoader();
    PGPSecretKey secretKey = kingRingLoader.load();
    PGPPublicKey publicKey = secretKey.getPublicKey();

    // This will a new "${artifact}.pem" file containing the
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (BCPGOutputStream os = new BCPGOutputStream(new ArmoredOutputStream(baos))) {
      publicKey.encode(os);
    }
    String publicKeyArmorContent = baos.toString();
    Path publicKeyArmorPath = artifact.resolveSibling(artifact.getFileName() + ".pem");
    writeString(publicKeyArmorPath, publicKeyArmorContent);
    resultBuilder.publicKeyContent(base64(publicKeyArmorContent.getBytes(StandardCharsets.UTF_8)));

    // This will produce a standard PGP armored "${artifact}.asc" file seen in Maven Central
    Path signaturePath = artifact.resolveSibling(artifact.getFileName() + ".asc");
    PgpArtifactSigner artifactSigner = new PgpArtifactSigner();
    // This will use a series of strategies to find the passphrase
    String signatureContent = artifactSigner.signToString(request.artifact().toFile());
    writeString(signaturePath, signatureContent);
    resultBuilder.artifactSignatureContent(base64(signatureContent.getBytes(StandardCharsets.UTF_8)));

    SigstoreResult result = resultBuilder.build();

    Map<String, Object> rekord = rekord(request, result);

    return ImmutableSigstoreResult.builder().from(result).rekorRecord(rekord).build();
  }
}
