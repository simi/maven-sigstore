package dev.sigstore.plugin;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Map;

import dev.sigstore.plugin.ImmutableSigstoreResult.Builder;
import io.takari.jpgp.PgpArtifactSigner;
import io.takari.jpgp.PgpKeyRingLoader;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;

import static dev.sigstore.plugin.Sign.base64;
import static dev.sigstore.plugin.Sign.sha256;
import static java.nio.file.Files.writeString;

public class PgpProcessor extends SigstoreProcessorSupport
{
    @Override
    public SigstoreResult process( SigstoreRequest request ) throws Exception
    {
        Builder resultBuilder = ImmutableSigstoreResult.builder();

        Path artifact = request.artifact();
        //
        // base64 content of artifact
        // sha256 hash of artifact
        // base64 of public key
        // base64 of signature
        //
        Path sha256Path = artifact.resolveSibling( artifact.getFileName() + ".sha256" );
        String sha256 = sha256( artifact );
        writeString( sha256Path, sha256);

        PgpKeyRingLoader kingRingLoader = new PgpKeyRingLoader();
        PGPSecretKey secretKey = kingRingLoader.load();
        PGPPublicKey publicKey = secretKey.getPublicKey();

        // This will a new "${artifact}.pem" file containing the
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (BCPGOutputStream os = new BCPGOutputStream(new ArmoredOutputStream(baos))) {
            publicKey.encode(os);
        }
        String publicKeyArmorContent = baos.toString();
        Path publicKeyArmorPath = artifact.resolveSibling( artifact.getFileName() + ".pem" );
        writeString( publicKeyArmorPath, publicKeyArmorContent );
        resultBuilder.publicKeyContent( base64(publicKeyArmorContent.getBytes( StandardCharsets.UTF_8 ) ) );

        // This will produce a standard PGP armored "${artifact}.asc" file seen in Maven Central
        Path signaturePath = artifact.resolveSibling( artifact.getFileName() + ".asc" );
        PgpArtifactSigner artifactSigner = new PgpArtifactSigner();
        // This will use a series of strategies to find the passphrase
        String signatureContent = artifactSigner.signToString( request.artifact().toFile());
        writeString( signaturePath, signatureContent );
        resultBuilder.artifactSignatureContent( base64(signatureContent.getBytes( StandardCharsets.UTF_8 )) );

        SigstoreResult result = resultBuilder.build();

        Map<String, Object> rekord = rekord( request, result );

        return ImmutableSigstoreResult.builder().from( result ).rekorRecord( rekord ).build();
    }
}
