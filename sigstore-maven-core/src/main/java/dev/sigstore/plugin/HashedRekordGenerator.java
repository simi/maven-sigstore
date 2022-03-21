
package dev.sigstore.plugin;

import static dev.sigstore.plugin.Sign.sha256;
import static org.apache.maven.sigstore.model.hashedrekord.Hash.Algorithm.SHA_256;

import java.util.HashMap;
import java.util.Map;
import org.apache.maven.sigstore.model.hashedrekord.Data;
import org.apache.maven.sigstore.model.hashedrekord.Hash;
import org.apache.maven.sigstore.model.hashedrekord.Hashedrekord;
import org.apache.maven.sigstore.model.hashedrekord.PublicKey;
import org.apache.maven.sigstore.model.hashedrekord.Signature;

public abstract class HashedRekordGenerator implements SigstoreProcessor {

  public static Map<String, Object> hashrekord(SigstoreRequest request, SigstoreResult result) throws Exception {
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
}
