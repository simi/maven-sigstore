package dev.sigstore.plugin;

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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.InvalidObjectException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.auth.openidconnect.IdTokenVerifier;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.http.ByteArrayContent;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpContent;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.apache.v2.ApacheHttpTransport;
import com.google.api.client.http.json.JsonHttpContent;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.PemReader;
import com.google.api.client.util.PemReader.Section;
import com.google.api.client.util.store.DataStoreFactory;
import com.google.api.client.util.store.MemoryDataStoreFactory;
import org.apache.commons.validator.routines.EmailValidator;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.maven.sigstore.model.rekord.Data;
import org.apache.maven.sigstore.model.rekord.Hash;
import org.apache.maven.sigstore.model.rekord.Rekord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// TODO:
// sha256 is incorrect and doesn't verify, as it's the sha256 of the signed JAR
// signature is a signed JAR file and not an actual signature
// http://tutorials.jenkov.com/java-cryptography/signature.html
// https://www.veracode.com/blog/research/digital-signatures-using-java

/**
 * Sign
 */
public class Sign
{
    public static final int HTTP_201 = 201;
    private static final Logger LOGGER = LoggerFactory.getLogger( Sign.class );

    private SigstoreRequest request;
    private SigstoreResult result;

    public static void main( String[] args ) throws Exception
    {
        SigstoreRequest request = ImmutableSigstoreRequest.builder()
                .emailAddress( "jason@vanzyl.ca" )
                .artifact( Paths.get(
                        "/Users/jvanzyl/js/provisio/maven-sigstore-site/maven-sigstore-plugin-0.0.1-SNAPSHOT.jar" ) )
                .build();

        Sign signer = new Sign( request );
        signer.executeSigstoreFlow();
    }

    public Sign( SigstoreRequest request )
    {
        this.request = request;
    }

    public void executeSigstoreFlow() throws Exception
    {
        result = ImmutableSigstoreResult.builder().build();

        // generate keypair
        result = generateKeyPair( request, result );

        // do OIDC dance, get ID token
        result = getIDToken( request, result );

        // sign email address with private key
        result = signEmailAddress( request, result );

        // push to fulcio, get signing cert chain
        result = getSigningCert( request, result );

        // sign JAR file here
        result = artifactSignature( request, result );

        // write signing certificate to file
        result = writeSigningCertToFile( request, result );

        // submit jar to rekor
        result = submitToRekor( request, result );

        LOGGER.info( String.format( "Created entry in transparency log for JAR @ '%s'", result.rekorEntryUrl() ) );
    }

    /**
     * Returns a new ephemeral keypair according to the plugin parameters
     */
    public SigstoreResult generateKeyPair( SigstoreRequest request, SigstoreResult result ) throws Exception
    {
        String signingAlgorithm = request.signingAlgorithm();
        String signingAlgorithmSpec = request.signingAlgorithmSpec();

        LOGGER.info( String.format( "generating keypair using %s with %s parameters", signingAlgorithm,
                signingAlgorithmSpec ) );
        try
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance( signingAlgorithm );
            AlgorithmParameterSpec aps;
            if ( "EC".equals( signingAlgorithm ) )
            {
                aps = new ECGenParameterSpec( signingAlgorithmSpec );
            }
            else
            {
                throw new IllegalArgumentException( String
                        .format( "unable to create signing algorithm spec for signing algorithm %s",
                                signingAlgorithm ) );
            }
            kpg.initialize( aps, new SecureRandom() );
            return ImmutableSigstoreResult.builder().from( result ).keyPair( kpg.generateKeyPair() ).build();
        }
        catch ( Exception e )
        {
            throw new Exception( "Error creating keypair:", e );
        }
    }

    /**
     * Signs the provided email address using the provided private key
     *
     * @return base64 encoded String containing the signature for the provided email address
     * @throws Exception If any exception happened during the signing process
     */
    public SigstoreResult signEmailAddress( SigstoreRequest request, SigstoreResult result ) throws Exception
    {
        PrivateKey privKey = result.keyPair().getPrivate();
        String emailAddress = result.emailAddress();

        try
        {
            EmailValidator ev = EmailValidator.getInstance();
            if ( !ev.isValid( emailAddress ) )
            {
                throw new IllegalArgumentException(
                        String.format( "email address specified '%s' is invalid", emailAddress ) );
            }
            LOGGER.info(
                    String.format( "signing email address '%s' as proof of possession of private key", emailAddress ) );
            Signature sig;
            if ( "EC".equals( privKey.getAlgorithm() ) )
            {
                sig = Signature.getInstance( "SHA256withECDSA" );
            }
            else
            {
                throw new NoSuchAlgorithmException(
                        String.format( "unable to generate signature for signing algorithm %s",
                                request.signingAlgorithm() ) );
            }
            sig.initSign( privKey );
            sig.update( emailAddress.getBytes() );
            return ImmutableSigstoreResult.builder().from( result )
                    .signedEmailAddress( Base64.getEncoder().encodeToString( sig.sign() ) ).build();
        }
        catch ( Exception e )
        {
            throw new Exception( String.format( "Error signing '%s': %s", emailAddress, e.getMessage() ), e );
        }
    }

    /**
     * Generates an HTTP Transport according to the requested SSL verification settings
     *
     * @return transport object with SSL verification enabled/disabled per the plugin parameter
     * <code>sslVerification</code>
     */
    public HttpTransport getHttpTransport()
    {
        HttpClientBuilder hcb = ApacheHttpTransport.newDefaultHttpClientBuilder();
        if ( !request.sslVerfication() )
        {
            hcb = hcb.setSSLHostnameVerifier( NoopHostnameVerifier.INSTANCE );
        }
        return new ApacheHttpTransport( hcb.build() );
    }

    /**
     * Obtains an OpenID Connect Identity Token from the OIDC provider specified in <code>oidcAuthURL</code>
     *
     * @return the ID token String (in JWS format)
     */
    public SigstoreResult getIDToken( SigstoreRequest request, SigstoreResult result ) throws Exception
    {
        String expectedEmailAddress = request.emailAddress();

        try
        {
            JsonFactory jsonFactory = new GsonFactory();
            HttpTransport httpTransport = getHttpTransport();
            DataStoreFactory memStoreFactory = new MemoryDataStoreFactory();

            final String idTokenKey = "id_token";

            if ( !request.oidcDeviceCodeFlow() )
            {
                AuthorizationCodeFlow.Builder flowBuilder = new AuthorizationCodeFlow.Builder(
                        BearerToken.authorizationHeaderAccessMethod(), httpTransport, jsonFactory,
                        new GenericUrl( request.oidcTokenURL().toString() ),
                        new ClientParametersAuthentication( request.oidcClientID(), null ),
                        request.oidcClientID(), request.oidcAuthURL().toString() )
                        .enablePKCE()
                        .setScopes( List.of( "openid", "email" ) )
                        .setCredentialCreatedListener(
                                ( credential, tokenResponse ) -> memStoreFactory.getDataStore( "user" ).set( idTokenKey,
                                        tokenResponse.get( idTokenKey ).toString() ) );
                AuthorizationCodeInstalledApp app = new AuthorizationCodeInstalledApp( flowBuilder.build(),
                        new LocalServerReceiver() );
                app.authorize( "user" );
            }
            // TODO: add device code flow support

            String idTokenString = (String) memStoreFactory.getDataStore( "user" ).get( idTokenKey );

            IdTokenVerifier idTokenVerifier = new IdTokenVerifier();
            IdToken parsedIdToken = IdToken.parse( jsonFactory, idTokenString );
            if ( !idTokenVerifier.verify( parsedIdToken ) )
            {
                throw new InvalidObjectException( "id token could not be verified" );
            }

            String emailFromIDToken = (String) parsedIdToken.getPayload().get( "email" );
            Boolean emailVerified = (Boolean) parsedIdToken.getPayload().get( "email_verified" );
            if ( expectedEmailAddress != null && !emailFromIDToken.equals( expectedEmailAddress ) )
            {
                throw new InvalidObjectException(
                        String.format( "email in ID token '%s' does not match address specified to plugin '%s'",
                                emailFromIDToken, request.emailAddress() ) );
            }
            else if ( Boolean.FALSE.equals( emailVerified ) )
            {
                throw new InvalidObjectException(
                        String.format( "identity provider '%s' reports email address '%s' has not been verified",
                                parsedIdToken.getPayload().getIssuer(), request.emailAddress() ) );
            }

            return ImmutableSigstoreResult.builder().from( result ).emailAddress( emailFromIDToken )
                    .rawIdToken( idTokenString ).build();
        }
        catch ( Exception e )
        {
            throw new Exception( "Error signing email address:", e );
        }
    }

    /**
     * Obtains a X509 code signing certificate signed by the Fulcio instance specified in
     * <code>fulcioInstanceURL</code>.
     *
     * @return The certificate chain including the code signing certificate
     * @throws Exception If any exception happened during the request for the code signing certificate
     */
    public SigstoreResult getSigningCert( SigstoreRequest request, SigstoreResult result ) throws Exception
    {
        PublicKey pubKey = result.keyPair().getPublic();
        String signedEmail = result.signedEmailAddress();
        String idToken = result.rawIdToken();

        try
        {
            HttpTransport httpTransport = getHttpTransport();

            String publicKeyB64 = Base64.getEncoder().encodeToString( pubKey.getEncoded() );
            Map<String, Object> fulcioPostContent = new HashMap<>();
            Map<String, Object> publicKeyContent = new HashMap<>();
            publicKeyContent.put( "content", publicKeyB64 );
            // TODO: look at signingAlgorithm and set accordingly
            if ( pubKey.getAlgorithm().equals( "EC" ) )
            {
                publicKeyContent.put( "algorithm", "ecdsa" );
            }

            fulcioPostContent.put( "signedEmailAddress", signedEmail );
            fulcioPostContent.put( "publicKey", publicKeyContent );
            JsonHttpContent jsonContent = new JsonHttpContent( new GsonFactory(), fulcioPostContent );
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            jsonContent.writeTo( stream );

            GenericUrl fulcioPostUrl = new GenericUrl( request.fulcioInstanceURL() + "/api/v1/signingCert" );
            HttpRequest req = httpTransport.createRequestFactory().buildPostRequest( fulcioPostUrl, jsonContent );

            req.getHeaders().set( "Accept", "application/pem-certificate-chain" );
            req.getHeaders().set( "Authorization", "Bearer " + idToken );

            LOGGER.info( "requesting signing certificate" );
            HttpResponse resp = req.execute();
            if ( resp.getStatusCode() != HTTP_201 )
            {
                throw new IOException(
                        String.format( "bad response from fulcio @ '%s' : %s", fulcioPostUrl, resp.parseAsString() ) );
            }

            LOGGER.info( "parsing signing certificate" );
            CertificateFactory cf = CertificateFactory.getInstance( "X.509" );
            ArrayList<X509Certificate> certList = new ArrayList<>();
            PemReader pemReader = new PemReader( new InputStreamReader( resp.getContent() ) );
            while ( true )
            {
                Section section = pemReader.readNextSection();
                if ( section == null )
                {
                    break;
                }
                byte[] certBytes = section.getBase64DecodedBytes();
                certList.add( (X509Certificate) cf.generateCertificate( new ByteArrayInputStream( certBytes ) ) );
            }
            if ( certList.isEmpty() )
            {
                throw new IOException( "no certificates were found in response from Fulcio instance" );
            }
            return ImmutableSigstoreResult.builder().from( result )
                    .signingCert( cf.generateCertPath( certList ) ).build();
        }
        catch ( Exception e )
        {
            throw new Exception(
                    String.format( "Error obtaining signing certificate from Fulcio @%s:",
                            request.fulcioInstanceURL() ), e );
        }
    }

    /**
     * Signs a JAR file using the private key; the provided certificate chain will be included in the signed JAR file
     *
     * @return The signed JAR file in byte array
     * @throws Exception If any exception happened during the JAR signing process
     */
    public SigstoreResult artifactSignature( SigstoreRequest request, SigstoreResult result ) throws Exception
    {
        try
        {
            File jarToSign = request.artifact().toFile();
            LOGGER.info( "Creating signature for artifact " + jarToSign.getAbsolutePath() );
            Signature signature = Signature.getInstance( "SHA256withECDSA" );
            signature.initSign( result.keyPair().getPrivate() );
            signature.update( Files.readAllBytes( request.artifact() ) );
            byte[] artifactSignatureBytes = signature.sign();
            String b64ArtifactSignatureContent = Base64.getEncoder().encodeToString( artifactSignatureBytes );
            Files.writeString( request.artifactSignature(), b64ArtifactSignatureContent );
            return ImmutableSigstoreResult.builder().from( result )
                    .artifactSignatureContent( b64ArtifactSignatureContent ).build();
        }
        catch ( Exception e )
        {
            throw new Exception( "Error signing JAR file:", e );
        }
    }

    /**
     * Writes the code signing certificate to a file
     *
     * @throws Exception If any exception happened during writing the certificate to the specified file
     */
    public SigstoreResult writeSigningCertToFile( SigstoreRequest request, SigstoreResult result ) throws Exception
    {
        CertPath certs = result.signingCert();
        File outputSigningCert = request.outputSigningCert().toFile();
        LOGGER.info( "writing signing certificate to " + outputSigningCert.getAbsolutePath() );
        try
        {
            final String lineSeparator = System.getProperty( "line.separator" );
            Base64.Encoder encoder = Base64.getMimeEncoder( 64, lineSeparator.getBytes() );
            // we only write the first one, not the entire chain
            byte[] rawCrtText = certs.getCertificates().get( 0 ).getEncoded();
            String encodedCertText = new String( encoder.encode( rawCrtText ) );
            String prettifiedCert = "-----BEGIN CERTIFICATE-----" + lineSeparator + encodedCertText + lineSeparator
                    + "-----END CERTIFICATE-----";
            String b64PublicKey = b64( prettifiedCert.getBytes( StandardCharsets.UTF_8 ) );
            Files.writeString( outputSigningCert.toPath(), prettifiedCert );
            return ImmutableSigstoreResult.builder().from( result ).signingCertContent( b64PublicKey ).build();
        }
        catch ( Exception e )
        {
            throw new Exception( String.format( "Error writing signing certificate to file '%s':",
                    outputSigningCert.getAbsolutePath() ), e );
        }

        // The generated outputSigning cert file should be moved from request to result
    }

    private String b64( byte[] input )
    {
        return Base64.getEncoder().encodeToString( input );
    }

    private String sha256( Path path ) throws Exception
    {
        MessageDigest digest = MessageDigest.getInstance( "SHA-256" );
        byte[] hash = digest.digest( Files.readAllBytes( path ) );
        StringBuilder hexString = new StringBuilder( 2 * hash.length );
        for ( int i = 0; i < hash.length; i++ )
        {
            String hex = Integer.toHexString( 0xff & hash[i] );
            if ( hex.length() == 1 )
            {
                hexString.append( '0' );
            }
            hexString.append( hex );
        }
        return hexString.toString();
    }

    /**
     * Submits the signature to a Rekor transparency log
     *
     * @return The URL where the entry in the transparency log can be seen for this signature/key combination
     * @throws Exception If any exception happened during interaction with the Rekor instance
     */
    public SigstoreResult submitToRekor( SigstoreRequest request, SigstoreResult result ) throws Exception
    {
        String artifactSignatureContent = result.artifactSignatureContent();
        PublicKey publicKey = result.keyPair().getPublic();

        try
        {
            HttpTransport httpTransport = getHttpTransport();
            String jarB64 = Base64.getEncoder().encodeToString( Files.readAllBytes( request.artifact() ) );

            Map<String, Object> rekorPostContent = new HashMap<>();
            rekorPostContent.put( "kind", "hashedrekord" );
            rekorPostContent.put( "apiVersion", "0.0.1" );

            // This is the spec
            Rekord h = new Rekord();
            h.setAdditionalProperty( "kind", "hashedrekord" );
            h.setAdditionalProperty( "apiVersion", "0.0.1" );

            rekorPostContent.put( "spec", h );

            // Data
            Data data = new Data();
            data.setContent( b64( Files.readAllBytes( request.artifact() ) ) );
            h.setAdditionalProperty( "spec", data );

            // Hash
            Hash hash = new Hash();
            hash.setValue( sha256( request.artifact() ) );
            hash.setAlgorithm( Hash.Algorithm.SHA_256 );
            data.setHash( hash );

            h.setData( data );

            org.apache.maven.sigstore.model.rekord.PublicKey p = new org.apache.maven.sigstore.model.rekord.PublicKey();
            p.setContent( result.signingCertContent() );


            // Signature
            org.apache.maven.sigstore.model.rekord.Signature s = new org.apache.maven.sigstore.model.rekord.Signature();
            s.setContent( artifactSignatureContent ); // jar signature
            s.setFormat( org.apache.maven.sigstore.model.rekord.Signature.Format.X_509 );
            s.setPublicKey( p );

            h.setSignature( s );

            //Map<String, Object> rekorPostContent = new HashMap<>();
            //Map<String, Object> specContent = new HashMap<>();
            //Map<String, Object> archiveContent = new HashMap<>();
            //archiveContent.put( "content", jarB64 );
            //specContent.put( "data", archiveContent );

            //rekorPostContent.put( "kind", "hashedrekord" );
            //rekorPostContent.put( "apiVersion", "0.0.1" );
            //rekorPostContent.put( "spec", specContent );

            ObjectMapper m = new ObjectMapper();

            String json = m.writerWithDefaultPrettyPrinter().writeValueAsString( rekorPostContent );
            System.out.println( json );
            byte[] rekorContent = json.getBytes( StandardCharsets.UTF_8 );
            HttpContent rekorJsonContent = new ByteArrayContent( null, rekorContent );
            //HttpContent rekorJsonContent2 = new JsonHttpContent( new GsonFactory(), rekorPostContent );

            System.out.println( m.writeValueAsString( rekorPostContent ) );

            ByteArrayOutputStream rekorStream = new ByteArrayOutputStream();
            rekorJsonContent.writeTo( rekorStream );

            GenericUrl rekorPostUrl = new GenericUrl( request.rekorInstanceURL() + "/api/v1/log/entries" );
            HttpRequest rekorReq =
                    httpTransport.createRequestFactory().buildPostRequest( rekorPostUrl, rekorJsonContent );

            rekorReq.getHeaders().set( "Accept", "application/json" );
            rekorReq.getHeaders().set( "Content-Type", "application/json" );

            HttpResponse rekorResp = rekorReq.execute();
            if ( rekorResp.getStatusCode() != HTTP_201 )
            {
                throw new IOException( "bad response from rekor: " + rekorResp.parseAsString() );
            }

            URL rekorEntryUrl = new URL( new URL( request.rekorInstanceURL() ), rekorResp.getHeaders().getLocation() );

            return ImmutableSigstoreResult.builder().from( result )
                    .rekorEntryUrl( rekorEntryUrl.toExternalForm() ).build();
        }
        catch ( Exception e )
        {
            throw new Exception(
                    String.format( "Error in submitting entry to Rekor @ %s:", request.rekorInstanceURL() ), e );
        }
    }
}
