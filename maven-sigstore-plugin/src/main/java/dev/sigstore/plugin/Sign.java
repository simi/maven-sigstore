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
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.InvalidObjectException;
import java.net.URL;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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
import java.util.function.BiConsumer;
import java.util.zip.ZipFile;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.openidconnect.IdToken;
import com.google.api.client.auth.openidconnect.IdTokenVerifier;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.http.GenericUrl;
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
import jdk.security.jarsigner.JarSigner;
import org.apache.commons.io.output.TeeOutputStream;
import org.apache.commons.validator.routines.EmailValidator;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.maven.shared.jarsigner.JarSignerUtil;
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

    private SigstoreRequest r;

    public static void main( String[] args ) throws Exception
    {
        SigstoreRequest r = ImmutableSigstoreRequest.builder()
                .emailAddress( "jason@vanzyl.ca" )
                .artifact( Paths.get("/Users/jvanzyl/js/provisio/maven-sigstore/maven-sigstore-plugin/target/maven-sigstore-plugin-0.0.1-SNAPSHOT.jar") )
                .outputSignedJar( Paths.get("/Users/jvanzyl/js/provisio/maven-sigstore/maven-sigstore-plugin/target/maven-sigstore-plugin-0.0.1-SNAPSHOT.jar.signed" ) )
                .build();

        Sign signer = new Sign(r);
        signer.executeSigstoreFlow();
    }

    public Sign( SigstoreRequest request )
    {
        this.r = request;
    }

    public void executeSigstoreFlow() throws Exception
    {
        // generate keypair
        KeyPair keypair = generateKeyPair( r.signingAlgorithm(), r.signingAlgorithmSpec() );

        // do OIDC dance, get ID token
        String rawIdToken = getIDToken( r.emailAddress() );

        // sign email address with private key
        String signedEmail = signEmailAddress( r.emailAddress(), keypair.getPrivate() );

        // push to fulcio, get signing cert chain
        CertPath certs = getSigningCert( signedEmail, keypair.getPublic(), rawIdToken );

        // sign JAR file here
        byte[] jarBytes = signJarFile( keypair.getPrivate(), certs );

        // write signing certificate to file
        writeSigningCertToFile( certs, r.outputSigningCert().toFile() );

        // submit jar to rekor
        submitToRekor( jarBytes );
    }

    /**
     * Returns a new ephemeral keypair according to the plugin parameters
     *
     * @param signingAlgorithm     an absolute URL giving the base location of the image
     * @param signingAlgorithmSpec the location of the image, relative to the url argument
     * @return the public and private keypair
     */
    public KeyPair generateKeyPair( String signingAlgorithm, String signingAlgorithmSpec ) throws Exception
    {
        LOGGER.info( String.format( "generating keypair using %s with %s parameters", signingAlgorithm,
                signingAlgorithmSpec ) );
        try
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance( signingAlgorithm );
            AlgorithmParameterSpec aps = null;
            switch ( signingAlgorithm )
            {
                case "EC":
                    aps = new ECGenParameterSpec( signingAlgorithmSpec );
                    break;
                default:
                    throw new IllegalArgumentException( String
                            .format( "unable to create signing algorithm spec for signing algorithm %s",
                                    signingAlgorithm ) );
            }
            kpg.initialize( aps, new SecureRandom() );
            return kpg.generateKeyPair();
        }
        catch ( Exception e )
        {
            throw new Exception( "Error creating keypair:", e );
        }
    }

    /**
     * Signs the provided email address using the provided private key
     *
     * @param emailAddress The email address to sign; this should match the email address in the OIDC token
     * @param privKey      The private key used to sign the email address
     * @return base64 encoded String containing the signature for the provided email address
     * @throws Exception If any exception happened during the signing process
     */
    public String signEmailAddress( String emailAddress, PrivateKey privKey ) throws Exception
    {
        try
        {
            if ( privKey == null )
            {
                throw new IllegalArgumentException( "private key must be specified" );
            }
            if ( emailAddress == null )
            {
                throw new IllegalArgumentException( "email address must not be null" );
            }
            else
            {
                EmailValidator ev = EmailValidator.getInstance();
                if ( !ev.isValid( emailAddress ) )
                {
                    throw new IllegalArgumentException(
                            String.format( "email address specified '%s' is invalid", emailAddress ) );
                }
            }
            LOGGER.info(
                    String.format( "signing email address '%s' as proof of possession of private key", emailAddress ) );
            Signature sig = null;
            switch ( privKey.getAlgorithm() )
            {
                case "EC":
                    sig = Signature.getInstance( "SHA256withECDSA" );
                    break;
                default:
                    throw new NoSuchAlgorithmException(
                            String.format( "unable to generate signature for signing algorithm %s",
                                    r.signingAlgorithm() ) );
            }
            sig.initSign( privKey );
            sig.update( emailAddress.getBytes() );
            return Base64.getEncoder().encodeToString( sig.sign() );
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
        if ( !r.sslVerfication() )
        {
            hcb = hcb.setSSLHostnameVerifier( NoopHostnameVerifier.INSTANCE );
        }
        return new ApacheHttpTransport( hcb.build() );
    }

    /**
     * Obtains an OpenID Connect Identity Token from the OIDC provider specified in <code>oidcAuthURL</code>
     *
     * @param expectedEmailAddress The email address we expected to see in the identity token
     * @return the ID token String (in JWS format)
     */
    public String getIDToken( String expectedEmailAddress ) throws Exception
    {
        try
        {
            JsonFactory jsonFactory = new GsonFactory();
            HttpTransport httpTransport = getHttpTransport();
            DataStoreFactory memStoreFactory = new MemoryDataStoreFactory();

            final String idTokenKey = "id_token";

            if ( !r.oidcDeviceCodeFlow() )
            {
                AuthorizationCodeFlow.Builder flowBuilder = new AuthorizationCodeFlow.Builder(
                        BearerToken.authorizationHeaderAccessMethod(), httpTransport, jsonFactory,
                        new GenericUrl( r.oidcTokenURL().toString() ),
                        new ClientParametersAuthentication( r.oidcClientID(), null ),
                        r.oidcClientID(), r.oidcAuthURL().toString() )
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
                                emailFromIDToken, r.emailAddress() ) );
            }
            else if ( Boolean.FALSE.equals( emailVerified ) )
            {
                throw new InvalidObjectException(
                        String.format( "identity provider '%s' reports email address '%s' has not been verified",
                                parsedIdToken.getPayload().getIssuer(), r.emailAddress() ) );
            }

            // bad side effect
            r = ImmutableSigstoreRequest.builder().from( r ).emailAddress( emailFromIDToken ).build();

            return idTokenString;
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
     * @param signedEmail a base64 encoded String containing the signed email address to associate with the requested
     *                    certificate
     * @param pubKey      the public key used to verify the signed email address; this key will be included in the final
     *                    certificate
     * @param idToken     a raw OIDC Identity token specified in JWS format
     * @return The certificate chain including the code signing certificate
     * @throws Exception If any exception happened during the request for the code signing certificate
     */
    public CertPath getSigningCert( String signedEmail, PublicKey pubKey, String idToken ) throws Exception
    {
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

            GenericUrl fulcioPostUrl = new GenericUrl( r.fulcioInstanceURL() + "/api/v1/signingCert" );
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
            return cf.generateCertPath( certList );
        }
        catch ( Exception e )
        {
            throw new Exception(
                    String.format( "Error obtaining signing certificate from Fulcio @%s:", r.fulcioInstanceURL() ), e );
        }
    }

    /**
     * Signs a JAR file using the private key; the provided certificate chain will be included in the signed JAR file
     *
     * @param privKey the private key that should be used to sign the JAR file
     * @param certs   The certificate chain including the code signing certificate which can be used to verify the
     *                signature
     * @return The signed JAR file in byte array
     * @throws Exception If any exception happened during the JAR signing process
     */
    public byte[] signJarFile( PrivateKey privKey, CertPath certs ) throws Exception
    {
        // sign JAR using keypair
        try
        {
            File jarToSign = r.artifact().toFile();
            LOGGER.info( "signing JAR file " + jarToSign.getAbsolutePath() );

            File outputJarFile;
            Boolean overwrite = true;
            if ( r.outputSignedJar() != null )
            {
                outputJarFile = r.outputSignedJar().toFile();
                overwrite = false;
            }
            else
            {
                outputJarFile = File.createTempFile( "signingTemp", ".jar", jarToSign.getParentFile() );
            }
            ByteArrayOutputStream memOut = new ByteArrayOutputStream();

            BiConsumer<String, String> progressLogger = ( op, entryName ) -> LOGGER
                    .debug( String.format( "%s %s", op, entryName ) );

            JarSigner.Builder jsb = new JarSigner.Builder( privKey, certs ).digestAlgorithm( "SHA-256" )
                    .signatureAlgorithm( "SHA256withECDSA" ).setProperty( "internalsf", "true" )
                    .signerName( r.signerName() )
                    .eventHandler( progressLogger );

            if ( r.tsaURL().toString().equals( "" ) )
            {
                jsb = jsb.tsa( new URL(r.tsaURL()).toURI() );
            }

            JarSigner js = jsb.build();
            try ( ZipFile in = new ZipFile( jarToSign );
                  FileOutputStream jarOut = new FileOutputStream( outputJarFile );
                  TeeOutputStream tee = new TeeOutputStream( jarOut, memOut ); )
            {
                js.sign( in, tee );
                if ( Boolean.TRUE.equals( overwrite ) )
                {
                    if ( !outputJarFile.renameTo( jarToSign ) )
                    {
                        throw new IOException( "error overwriting unsigned JAR" );
                    }
                    LOGGER.info( "wrote signed JAR to " + jarToSign.getAbsolutePath() );
                    if ( !JarSignerUtil.isArchiveSigned( jarToSign ) )
                    {
                        throw new VerifyError( "JAR signing verification failed" );
                    }
                }
                else
                {
                    LOGGER.info( "wrote signed JAR to " + r.outputSignedJar().toString() );
                    if ( !JarSignerUtil.isArchiveSigned( r.outputSignedJar().toFile() ) )
                    {
                        throw new VerifyError( "JAR signing verification failed" );
                    }
                }
            }

            return memOut.toByteArray();
        }
        catch ( Exception e )
        {
            throw new Exception( "Error signing JAR file:", e );
        }
    }

    /**
     * Writes the code signing certificate to a file
     *
     * @param certs             The certificate chain including the code signing certificate which can be used to verify
     *                          the signature
     * @param outputSigningCert The file where the code signing cert should be written to
     * @throws Exception If any exception happened during writing the certificate to the specified file
     */
    public void writeSigningCertToFile( CertPath certs, File outputSigningCert ) throws Exception
    {
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

            if ( !outputSigningCert.createNewFile() )
            {
                throw new IOException( String.format( "file at %s already exists; will not overwrite",
                        outputSigningCert.getAbsolutePath() ) );
            }
            try ( FileWriter fw = new FileWriter( outputSigningCert ) )
            {
                fw.write( prettifiedCert );
            }
        }
        catch ( Exception e )
        {
            throw new Exception( String.format( "Error writing signing certificate to file '%s':",
                    outputSigningCert.getAbsolutePath() ), e );
        }
    }

    /**
     * Submits the signature to a Rekor transparency log
     *
     * @param jarBytes The signed JAR file in a byte array
     * @return The URL where the entry in the transparency log can be seen for this signature/key combination
     * @throws Exception If any exception happened during interaction with the Rekor instance
     */
    public URL submitToRekor( byte[] jarBytes ) throws Exception
    {
        try
        {
            HttpTransport httpTransport = getHttpTransport();

            String jarB64 = Base64.getEncoder().encodeToString( jarBytes );
            Map<String, Object> rekorPostContent = new HashMap<>();
            Map<String, Object> specContent = new HashMap<>();
            Map<String, Object> archiveContent = new HashMap<>();
            archiveContent.put( "content", jarB64 );
            specContent.put( "data", archiveContent );

            rekorPostContent.put( "kind", "jar" );
            rekorPostContent.put( "apiVersion", "0.0.1" );
            rekorPostContent.put( "spec", specContent );
            JsonHttpContent rekorJsonContent = new JsonHttpContent( new GsonFactory(), rekorPostContent );
            ByteArrayOutputStream rekorStream = new ByteArrayOutputStream();
            rekorJsonContent.writeTo( rekorStream );

            GenericUrl rekorPostUrl = new GenericUrl( r.rekorInstanceURL() + "/api/v1/log/entries" );
            HttpRequest rekorReq =
                    httpTransport.createRequestFactory().buildPostRequest( rekorPostUrl, rekorJsonContent );

            rekorReq.getHeaders().set( "Accept", "application/json" );
            rekorReq.getHeaders().set( "Content-Type", "application/json" );

            HttpResponse rekorResp = rekorReq.execute();
            if ( rekorResp.getStatusCode() != HTTP_201 )
            {
                throw new IOException( "bad response from rekor: " + rekorResp.parseAsString() );
            }

            URL rekorEntryUrl = new URL( new URL(r.rekorInstanceURL()), rekorResp.getHeaders().getLocation() );
            LOGGER.info( String.format( "Created entry in transparency log for JAR @ '%s'", rekorEntryUrl ) );
            return rekorEntryUrl;
        }
        catch ( Exception e )
        {
            throw new Exception(
                    String.format( "Error in submitting entry to Rekor @ %s:", r.rekorInstanceURL() ), e );
        }
    }
}
