package dev.sigstore;

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import static dev.sigstore.SigstoreSigner.base64;
import static dev.sigstore.SigstoreSigner.sha256;
import static org.apache.maven.sigstore.model.hashedrekord.Hash.Algorithm.SHA_256;

import dev.sigstore.SigstoreRequest.Type;
import java.util.HashMap;
import java.util.Map;
import org.apache.maven.sigstore.model.hashedrekord.Data;
import org.apache.maven.sigstore.model.hashedrekord.Hash;
import org.apache.maven.sigstore.model.hashedrekord.Hashedrekord;
import org.apache.maven.sigstore.model.hashedrekord.PublicKey;
import org.apache.maven.sigstore.model.hashedrekord.Signature;
import org.apache.maven.sigstore.model.rekord.Hash.Algorithm;
import org.apache.maven.sigstore.model.rekord.Rekord;
import org.apache.maven.sigstore.model.rekord.Signature.Format;

public abstract class SigstoreProcessorSupport implements SigstoreProcessor {

  //TODO: make this use the implementations not the other way around
  protected Map<String, Object> rekord(SigstoreRequest request, SigstoreResult result) throws Exception {
    return generateHashedRekord(request, result);
  }

  protected Map<String, Object> generateHashedRekord(SigstoreRequest request, SigstoreResult result) throws Exception {
    // {
    //   "apiVersion" : "0.0.1",
    //   "kind" : "hashedrekord",
    //   "spec" : {
    //     "signature" : {
    //       "format" : "x509",
    //       "content" : "base64 <content>",
    //       "publicKey" : {
    //         "content" : "base64 <content>"
    //       }
    //     },
    //     "data" : {
    //       "hash" : {
    //         "algorithm" : "sha256",
    //         "value" : "916ea454120422182823bd4bca3331f5a544d90914c9992362f1b10b56b268c4"
    //       }
    //     }
    //   }
    // }

    Map<String, Object> rekord = new HashMap<>();
    rekord.put("kind", "hashedrekord");
    rekord.put("apiVersion", "0.0.1");
    rekord.put("spec", new Hashedrekord()
        .withData(new Data()
            .withHash(new Hash()
                .withValue(sha256(request.artifact()))
                .withAlgorithm(SHA_256)))
        .withSignature(new Signature()
            .withContent(result.artifactSignatureContent())
            .withPublicKey(new PublicKey()
                .withContent(result.publicKeyContent()))));
    return rekord;
  }

  protected Map<String, Object> generateRekord(SigstoreRequest request, SigstoreResult result) throws Exception {
    // {
    //   "apiVersion" : "0.0.1",
    //   "kind" : "rekord",
    //   "spec" : {
    //     "signature" : {
    //       "format" : "x509",
    //       "content" : "base64 <content>",
    //       "publicKey" : {
    //         "content" : "base64 <content>"
    //       }
    //     },
    //     "data" : {
    //       "hash" : {
    //         "algorithm" : "sha256",
    //         "value" : "916ea454120422182823bd4bca3331f5a544d90914c9992362f1b10b56b268c4"
    //       },
    //       "content" : "base64 <content>"
    //     }
    //   }
    // }

    Map<String, Object> rekord = new HashMap<>();
    rekord.put("kind", "rekord");
    rekord.put("apiVersion", "0.0.1");
    rekord.put("spec", new Rekord()
        .withData(new org.apache.maven.sigstore.model.rekord.Data()
            .withContent(base64(request.artifact()))
            .withHash(new org.apache.maven.sigstore.model.rekord.Hash()
                .withValue(sha256(request.artifact()))
                .withAlgorithm(Algorithm.SHA_256)))
        .withSignature(new org.apache.maven.sigstore.model.rekord.Signature()
            .withFormat(from(request.type()))
            .withContent(result.artifactSignatureContent())
            .withPublicKey(new org.apache.maven.sigstore.model.rekord.PublicKey()
                .withContent(result.publicKeyContent()))));
    return rekord;
  }

  private Format from(SigstoreRequest.Type type) {
    if (type.equals(Type.X_509)) {
      return Format.X_509;
    }
    if (type.equals(Type.SSH)) {
      return Format.SSH;
    }
    if (type.equals(Type.PGP)) {
      return Format.PGP;
    }
    throw new IllegalArgumentException("Unsupported type " + type);
  }
}
