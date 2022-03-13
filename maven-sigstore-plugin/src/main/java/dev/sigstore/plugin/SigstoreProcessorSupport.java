
package dev.sigstore.plugin;

import java.util.HashMap;
import java.util.Map;

import org.apache.maven.sigstore.model.rekord.Data;
import org.apache.maven.sigstore.model.rekord.Hash;
import org.apache.maven.sigstore.model.rekord.PublicKey;
import org.apache.maven.sigstore.model.rekord.Rekord;
import org.apache.maven.sigstore.model.rekord.Signature;

import static dev.sigstore.plugin.Sign.base64;
import static dev.sigstore.plugin.Sign.sha256;
import static org.apache.maven.sigstore.model.rekord.Hash.Algorithm.SHA_256;

public abstract class SigstoreProcessorSupport implements SigstoreProcessor
{
    protected Map<String, Object> rekord( SigstoreRequest request, SigstoreResult result ) throws Exception
    {
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
        rekord.put( "kind", "rekord" );
        rekord.put( "apiVersion", "0.0.1" );
        rekord.put( "spec", new Rekord()
                .withData( new Data()
                        .withContent( base64( request.artifact() ) )
                        .withHash( new Hash()
                                .withValue( sha256( request.artifact() ) )
                                .withAlgorithm( SHA_256 ) ) )
                .withSignature( new Signature()
                        .withFormat( request.type() )
                        .withContent( result.artifactSignatureContent() )
                        .withPublicKey( new PublicKey()
                                .withContent( result.publicKeyContent() ) ) ) );
        return rekord;
    }
}
