package dev.sigstore.plugin;

import static dev.sigstore.plugin.Sign.HTTP_201;
import static dev.sigstore.plugin.Sign.base64;
import static dev.sigstore.plugin.Sign.getHttpTransport;
import static dev.sigstore.plugin.Sign.newResultFrom;
import static java.lang.String.format;

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
import com.google.api.client.http.json.JsonHttpContent;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.PemReader;
import com.google.api.client.util.store.DataStoreFactory;
import com.google.api.client.util.store.MemoryDataStoreFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.InvalidObjectException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
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
import org.apache.commons.validator.routines.EmailValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FulcioProcessor extends SigstoreProcessorSupport {

  private static final Logger logger = LoggerFactory.getLogger(FulcioProcessor.class);

  @Override
  public SigstoreResult process(SigstoreRequest request) throws Exception {
    SigstoreResult result = ImmutableSigstoreResult.builder().build();
    result = acquireKeyPair(request, result);
    result = getIDToken(request, result);
    result = signEmailAddress(request, result);
    result = retrieveFulcioSigningCertificate(request, result);
    result = saveFulcioSigningCertificateToDisk(request, result);
    result = generateArtifactSignature(request, result);
    Map<String, Object> rekord = rekord(request, result);
    return ImmutableSigstoreResult.builder().from(result).rekorRecord(rekord).build();
  }

  /**
   * Returns a new ephemeral keypair according to the plugin parameters
   */
  private SigstoreResult acquireKeyPair(SigstoreRequest request, SigstoreResult result) throws Exception {
    String signingAlgorithm = request.signingAlgorithm();
    String signingAlgorithmSpec = request.signingAlgorithmSpec();
    logger.info(format("generating keypair using %s with %s parameters", signingAlgorithm, signingAlgorithmSpec));
    try {
      KeyPairGenerator kpg = KeyPairGenerator.getInstance(signingAlgorithm);
      AlgorithmParameterSpec aps;
      if ("EC".equals(signingAlgorithm)) {
        aps = new ECGenParameterSpec(signingAlgorithmSpec);
      } else {
        throw new IllegalArgumentException(format("unable to create signing algorithm spec for signing algorithm %s", signingAlgorithm));
      }
      kpg.initialize(aps, new SecureRandom());
      return newResultFrom(result).keyPair(kpg.generateKeyPair()).build();
    } catch (Exception e) {
      throw new Exception("Error creating keypair:", e);
    }
  }

  /**
   * Obtains an OpenID Connect Identity Token from the OIDC provider specified in <code>oidcAuthURL</code>
   *
   * @return the ID token String (in JWS format)
   */
  private SigstoreResult getIDToken(SigstoreRequest request, SigstoreResult result) throws Exception {
    String expectedEmailAddress = request.emailAddress();
    try {
      JsonFactory jsonFactory = new GsonFactory();
      HttpTransport httpTransport = getHttpTransport(request);
      DataStoreFactory memStoreFactory = new MemoryDataStoreFactory();

      String idTokenString;
      String idTokenEnvar = System.getenv("ID_TOKEN");
      System.out.println("idTokenEnvar = " + idTokenEnvar);
      if (idTokenEnvar != null) {
        idTokenString = idTokenEnvar;
      } else {
        final String idTokenKey = "id_token";
        if (!request.oidcDeviceCodeFlow()) {
          AuthorizationCodeFlow.Builder flowBuilder = new AuthorizationCodeFlow.Builder(
              BearerToken.authorizationHeaderAccessMethod(), httpTransport, jsonFactory,
              new GenericUrl(request.oidcTokenURL()),
              new ClientParametersAuthentication(request.oidcClientID(), null),
              request.oidcClientID(), request.oidcAuthURL())
              .enablePKCE()
              .setScopes(List.of("openid", "email"))
              .setCredentialCreatedListener(
                  (credential, tokenResponse) -> memStoreFactory.getDataStore("user").set(idTokenKey,
                      tokenResponse.get(idTokenKey).toString()));
          AuthorizationCodeInstalledApp app = new AuthorizationCodeInstalledApp(flowBuilder.build(), new LocalServerReceiver());
          app.authorize("user");
        }
        idTokenString = (String) memStoreFactory.getDataStore("user").get(idTokenKey);
      }
      System.out.println("1");
      IdTokenVerifier idTokenVerifier = new IdTokenVerifier();
      IdToken parsedIdToken = IdToken.parse(jsonFactory, idTokenString);
      System.out.println("2");
      if (!idTokenVerifier.verify(parsedIdToken)) {
        throw new InvalidObjectException("id token could not be verified");
      }

      System.out.println("3");
      String emailFromIDToken = (String) parsedIdToken.getPayload().get("email");
      if (emailFromIDToken != null) {
        System.out.println("emailFromIDToken = " + emailFromIDToken);
        System.out.println("4");
        Boolean emailVerified = (Boolean) parsedIdToken.getPayload().get("email_verified");
        System.out.println(emailVerified);
        System.out.println("5");
        if (expectedEmailAddress != null && !emailFromIDToken.equals(expectedEmailAddress)) {
          throw new InvalidObjectException(
              format("email in ID token '%s' does not match address specified to plugin '%s'",
                  emailFromIDToken, request.emailAddress()));

        } else if (Boolean.FALSE.equals(emailVerified)) {
          throw new InvalidObjectException(
              format("identity provider '%s' reports email address '%s' has not been verified",
                  parsedIdToken.getPayload().getIssuer(), request.emailAddress()));
        }
        return newResultFrom(result).emailAddress(emailFromIDToken).rawIdToken(idTokenString).build();
      } else {
        return newResultFrom(result).emailAddress(request.emailAddress()).rawIdToken(idTokenString).build();
      }
    } catch (Exception e) {
      throw new Exception("Error signing email address:", e);
    }
  }

  /**
   * Signs the provided email address using the provided private key
   *
   * @return base64 encoded String containing the signature for the provided email address
   * @throws Exception If any exception happened during the signing process
   */
  private SigstoreResult signEmailAddress(SigstoreRequest request, SigstoreResult result) throws Exception {
    PrivateKey privKey = result.keyPair().getPrivate();
    String emailAddress = result.emailAddress();

    try {
      EmailValidator ev = EmailValidator.getInstance();
      if (!ev.isValid(emailAddress)) {
        throw new IllegalArgumentException(
            format("email address specified '%s' is invalid", emailAddress));
      }
      logger.info(format("signing email address '%s' as proof of possession of private key", emailAddress));
      Signature sig;
      if ("EC".equals(privKey.getAlgorithm())) {
        sig = Signature.getInstance("SHA256withECDSA");
      } else {
        throw new NoSuchAlgorithmException(
            format("unable to generate signature for signing algorithm %s",
                request.signingAlgorithm()));
      }
      sig.initSign(privKey);
      sig.update(emailAddress.getBytes());
      return newResultFrom(result).signedEmailAddress(base64(sig.sign())).build();
    } catch (Exception e) {
      throw new Exception(format("Error signing '%s': %s", emailAddress, e.getMessage()), e);
    }
  }

  /**
   * Obtains a X509 code signing certificate signed by the Fulcio instance specified in
   * <code>fulcioInstanceURL</code>.
   *
   * @return The certificate chain including the code signing certificate
   * @throws Exception If any exception happened during the request for the code signing certificate
   */
  private SigstoreResult retrieveFulcioSigningCertificate(SigstoreRequest request, SigstoreResult result)
      throws Exception {
    PublicKey pubKey = result.keyPair().getPublic();
    String signedEmail = result.signedEmailAddress();
    String idToken = result.rawIdToken();

    try {
      String publicKeyB64 = Base64.getEncoder().encodeToString(pubKey.getEncoded());
      Map<String, Object> fulcioPostContent = new HashMap<>();
      Map<String, Object> publicKeyContent = new HashMap<>();
      publicKeyContent.put("content", publicKeyB64);
      // TODO: look at signingAlgorithm and set accordingly
      if (pubKey.getAlgorithm().equals("EC")) {
        publicKeyContent.put("algorithm", "ecdsa");
      }

      fulcioPostContent.put("signedEmailAddress", signedEmail);
      fulcioPostContent.put("publicKey", publicKeyContent);
      JsonHttpContent jsonContent = new JsonHttpContent(new GsonFactory(), fulcioPostContent);
      ByteArrayOutputStream stream = new ByteArrayOutputStream();
      jsonContent.writeTo(stream);

      GenericUrl fulcioPostUrl = new GenericUrl(request.fulcioInstanceURL() + "/api/v1/signingCert");
      HttpRequest req = getHttpTransport(request).createRequestFactory().buildPostRequest(fulcioPostUrl, jsonContent);
      req.getHeaders().set("Accept", "application/pem-certificate-chain");
      req.getHeaders().set("Authorization", "Bearer " + idToken);

      logger.info("requesting signing certificate");
      HttpResponse resp = req.execute();
      if (resp.getStatusCode() != HTTP_201) {
        throw new IOException(
            format("bad response from fulcio @ '%s' : %s", fulcioPostUrl, resp.parseAsString()));
      }

      logger.info("parsing signing certificate");
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      ArrayList<X509Certificate> certList = new ArrayList<>();
      PemReader pemReader = new PemReader(new InputStreamReader(resp.getContent()));
      while (true) {
        PemReader.Section section = pemReader.readNextSection();
        if (section == null) {
          break;
        }
        byte[] certBytes = section.getBase64DecodedBytes();
        certList.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes)));
      }
      if (certList.isEmpty()) {
        throw new IOException("no certificates were found in response from Fulcio instance");
      }
      return newResultFrom(result).signingCert(cf.generateCertPath(certList)).build();
    } catch (Exception e) {
      throw new Exception(
          format("Error obtaining signing certificate from Fulcio @%s:",
              request.fulcioInstanceURL()), e);
    }
  }

  /**
   * Writes the code signing certificate to a file
   *
   * @throws Exception If any exception happened during writing the certificate to the specified file
   */
  private SigstoreResult saveFulcioSigningCertificateToDisk(SigstoreRequest request, SigstoreResult result)
      throws Exception {
    CertPath certs = result.signingCert();
    File outputSigningCert = request.outputSigningCert().toFile();
    logger.info("writing signing certificate to " + outputSigningCert.getAbsolutePath());
    try {
      final String lineSeparator = System.getProperty("line.separator");
      Base64.Encoder encoder = Base64.getMimeEncoder(64, lineSeparator.getBytes());
      // we only write the first one, not the entire chain
      byte[] rawCrtText = certs.getCertificates().get(0).getEncoded();
      String encodedCertText = new String(encoder.encode(rawCrtText));
      String prettifiedCert = "-----BEGIN CERTIFICATE-----" + lineSeparator + encodedCertText + lineSeparator
          + "-----END CERTIFICATE-----";
      String b64PublicKey = base64(prettifiedCert.getBytes(StandardCharsets.UTF_8));
      Files.writeString(outputSigningCert.toPath(), prettifiedCert);
      return newResultFrom(result).publicKeyContent(b64PublicKey).build();
    } catch (Exception e) {
      throw new Exception(format("Error writing signing certificate to file '%s':",
          outputSigningCert.getAbsolutePath()), e);
    }
  }

  /**
   * Signs a JAR file using the private key; the provided certificate chain will be included in the signed JAR file
   *
   * @return The signed JAR file in byte array
   * @throws Exception If any exception happened during the JAR signing process
   */
  private SigstoreResult generateArtifactSignature(SigstoreRequest request, SigstoreResult result) throws Exception {
    try {
      File jarToSign = request.artifact().toFile();
      logger.info("Creating signature for artifact " + jarToSign.getAbsolutePath());
      Signature signature = Signature.getInstance("SHA256withECDSA");
      signature.initSign(result.keyPair().getPrivate());
      signature.update(Files.readAllBytes(request.artifact()));
      byte[] artifactSignatureBytes = signature.sign();
      String b64ArtifactSignatureContent = Base64.getEncoder().encodeToString(artifactSignatureBytes);
      Files.writeString(request.artifactSignature(), b64ArtifactSignatureContent);
      return newResultFrom(result).artifactSignatureContent(b64ArtifactSignatureContent).build();
    } catch (Exception e) {
      throw new Exception("Error signing JAR file:", e);
    }
  }
}
