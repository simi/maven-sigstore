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

import static java.lang.String.format;

import java.io.File;
import java.net.URL;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Goal which: - generates ephemeral key pair - requests code signing
 * certificate from sigstore Fulcio - signs the JAR file - publishes signature
 * to sigstore rekor - verifies the signed JAR
 */
@Mojo( name = "sign", defaultPhase = LifecyclePhase.PACKAGE )
public class SignMojo extends AbstractMojo
{
    public static Logger logger = LoggerFactory.getLogger(SignMojo.class);

    /**
     * Reference to maven project; will be used to find JAR file to be signed unless
     * specified in input-jar
     */
    @Parameter( defaultValue = "${project}", readonly = true, required = true )
    private MavenProject project;

    /**
     * Location of the input JAR file. defaults to default project artifact
     */
    @Parameter( property = "input-jar" )
    private File inputJar;

    /**
     * Location of the signed JAR file; defaults to overwriting the input file with
     * the signed JAR
     */
    @Parameter( property = "output-signed-jar" )
    private File outputSignedJar;

    /**
     * Location of the code signing certificate (including public key) used to
     * verify signature
     */
    @Parameter( defaultValue = "${project.build.directory}/signingCert.pem", property = "output-signing-cert",
                required = true )
    private File outputSigningCert;

    /**
     * Signing algorithm to be used; default is ECDSA
     */
    @Parameter( defaultValue = "sigstore", property = "signer-name", required = true )
    private String signerName;

    /**
     * Signing algorithm to be used; default is ECDSA
     */
    @Parameter( defaultValue = "EC", property = "signing-algorithm", required = true )
    private String signingAlgorithm;

    /**
     * Signing algorithm specification to be used; default is secp256r1
     */
    @Parameter( defaultValue = "secp256r1", property = "signing-algorithm-spec", required = true )
    private String signingAlgorithmSpec;

    /**
     * Enable/disable SSL hostname verification
     */
    @Parameter( defaultValue = "true", property = "ssl-verification", required = true )
    private boolean sslVerfication;

    /**
     * URL of Fulcio instance
     */
    @Parameter( defaultValue = "https://fulcio.sigstore.dev", property = "fulcio-instance-url", required = true )
    private URL fulcioInstanceURL;

    /**
     * Use browser-less OAuth Device Code flow instead of opening local browser
     */
    @Parameter( defaultValue = "false", property = "oidc-device-code", required = true )
    private boolean oidcDeviceCodeFlow;

    /**
     * Client ID for OIDC Identity Provider
     */
    @Parameter( defaultValue = "sigstore", property = "oidc-client-id", required = true )
    private String oidcClientID;

    /**
     * URL of OIDC Identity Provider Authorization endpoint
     */
    @Parameter( defaultValue = "https://oauth2.sigstore.dev/auth/auth", property = "oidc-auth-url", required = true )
    private URL oidcAuthURL;

    /**
     * URL of OIDC Identity Provider Token endpoint
     */
    @Parameter( defaultValue = "https://oauth2.sigstore.dev/auth/token", property = "oidc-token-url", required = true )
    private URL oidcTokenURL;

    /**
     * URL of OIDC Identity Provider Device Code endpoint
     */
    @Parameter( defaultValue = "https://oauth2.sigstore.dev/auth/device/code", property = "oidc-device-code-url", required = true )
    private URL oidcDeviceCodeURL;

    /**
     * URL of Rekor instance
     */
    @Parameter( defaultValue = "https://rekor.sigstore.dev", property = "rekor-instance-url", required = true )
    private URL rekorInstanceURL;

    /**
     * Email address of signer; if not specified, the email address returned in the OIDC identity token will be used
     */
    @Parameter( property = "email-address" )
    private String emailAddress;

    /**
     * URL of Trusted Timestamp Authority (RFC3161 compliant)
     */
    @Parameter( defaultValue = "https://rekor.sigstore.dev/api/v1/timestamp", property = "tsa-url", required = true )
    private URL tsaURL;

    public void execute() throws MojoExecutionException
    {
       SigstoreRequest request = ImmutableSigstoreRequest.builder()
           .build();

       try {
           SigstoreResult result = new Sign(request).executeSigstoreFlow();
           logger.info(format("Created entry in transparency log for JAR @ '%s'", result.rekorEntryUrl()));
       } catch(Exception e) {
            throw new MojoExecutionException(e);
       }
    }
}
