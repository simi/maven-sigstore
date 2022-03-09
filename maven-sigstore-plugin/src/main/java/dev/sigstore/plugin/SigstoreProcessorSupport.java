package dev.sigstore.plugin;

import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;

import org.apache.maven.sigstore.model.rekord.Data;
import org.apache.maven.sigstore.model.rekord.Hash;
import org.apache.maven.sigstore.model.rekord.PublicKey;
import org.apache.maven.sigstore.model.rekord.Rekord;
import org.apache.maven.sigstore.model.rekord.Signature;

import static dev.sigstore.plugin.Sign.b64;
import static dev.sigstore.plugin.Sign.sha256;
import static org.apache.maven.sigstore.model.rekord.Signature.Format.PGP;
import static org.apache.maven.sigstore.model.rekord.Signature.Format.X_509;

/*

{
  "apiVersion" : "0.0.1",
  "kind" : "rekord",
  "spec" : {
    "signature" : {
      "format" : "x509",
      "content" : "MEUCID1OPssq/rTDlcVZBS4oidCattXXKLhzG/y94b/u9eIvAiEA5Q6e1r0nbo61BDiUIGgIm0MyPSKCEBQisQbmrUq7gMA=",
      "publicKey" : {
        "content" : "xxx"
      }
    },
    "data" : {
      "hash" : {
        "algorithm" : "sha256",
        "value" : "916ea454120422182823bd4bca3331f5a544d90914c9992362f1b10b56b268c4"
      },
      "content" : "xxx"
    }
  }
}

*/

public abstract class SigstoreProcessorSupport implements SigstoreProcessor
{
    protected Map<String, Object> rekord( SigstoreRequest request, SigstoreResult result ) throws Exception
    {
        //
        // base64 content of artifact
        // sha256 hash of artifact
        // base64 of public key
        // base64 of signature
        //

        // Entry
        Map<String, Object> rekord = new HashMap<>();
        rekord.put( "kind", "rekord" );
        rekord.put( "apiVersion", "0.0.1" );

        // Spec
        Rekord spec = new Rekord();
        rekord.put( "spec", spec );

        // Data
        Data data = new Data();
        data.setContent( b64( Files.readAllBytes( request.artifact() ) ) );
        spec.setData( data );

        // Hash
        Hash hash = new Hash();
        hash.setValue( sha256( request.artifact() ) );
        hash.setAlgorithm( Hash.Algorithm.SHA_256 );
        data.setHash( hash );

        // Signature
        Signature signature = new Signature();
        signature.setContent( result.artifactSignatureContent() );
        if ( request.type().equals( Type.X_509 ) )
        {
            signature.setFormat( X_509 );
        }
        else if ( request.type().equals( Type.PGP ) )
        {
            signature.setFormat( PGP );
        }
        spec.setSignature( signature );

        // PublicKey
        PublicKey publicKey = new PublicKey();
        publicKey.setContent( result.publicKeyContent() );
        signature.setPublicKey( publicKey );

        return rekord;
    }
}
