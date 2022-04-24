package dev.sigstore.x509;

import static dev.sigstore.SigstoreSigner.HTTP_201;
import static dev.sigstore.SigstoreSigner.base64;
import static dev.sigstore.SigstoreSigner.getHttpTransport;
import static dev.sigstore.SigstoreSigner.newResultFrom;
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
import dev.sigstore.ImmutableSigstoreResult;
import dev.sigstore.SigstoreProcessorSupport;
import dev.sigstore.SigstoreRequest;
import dev.sigstore.SigstoreResult;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FulcioProcessor extends SigstoreProcessorSupport {

  private static final Logger logger = LoggerFactory.getLogger(FulcioProcessor.class);

  @Override
  public SigstoreResult process(SigstoreRequest request) throws Exception {
    SigstoreResult result = ImmutableSigstoreResult.builder().build();
    result = generateKeyPair(request, result);
    result = getIDToken(request, result);
    result = signSubject(request, result);
    result = retrieveFulcioSigningCertificate(request, result);
    result = saveFulcioSigningCertificateToDisk(request, result);
    result = generateArtifactSignature(request, result);
    Map<String, Object> rekord = rekord(request, result);
    return ImmutableSigstoreResult.builder().from(result).rekorRecord(rekord).build();
  }

  private SigstoreResult generateKeyPair(SigstoreRequest request, SigstoreResult result) throws Exception {
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
      IdTokenVerifier idTokenVerifier = new IdTokenVerifier();
      IdToken parsedIdToken = IdToken.parse(jsonFactory, idTokenString);
      if (!idTokenVerifier.verify(parsedIdToken)) {
        throw new InvalidObjectException("id token could not be verified");
      }

      // So this verifies
      String emailFromIDToken = (String) parsedIdToken.getPayload().get("email");
      if (emailFromIDToken != null) {
        System.out.println("emailFromIDToken = " + emailFromIDToken);
        Boolean emailVerified = (Boolean) parsedIdToken.getPayload().get("email_verified");
        System.out.println(emailVerified);
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
        String subject = parsedIdToken.getPayload().getSubject();
        System.out.println("using subject of " + subject);
        return newResultFrom(result).emailAddress(subject).rawIdToken(idTokenString).build();
      }
    } catch (Exception e) {
      throw new Exception("Error signing email address:", e);
    }
  }

  private SigstoreResult signSubject(SigstoreRequest request, SigstoreResult result) throws Exception {
    PrivateKey privateKey = result.keyPair().getPrivate();
    String subject = result.emailAddress();
    logger.debug("request.emailAddress() = " + request.emailAddress());

    //EmailValidator ev = EmailValidator.getInstance();
    //if (!ev.isValid(emailAddress)) {
    //  throw new IllegalArgumentException(
    //      format("email address specified '%s' is invalid", emailAddress));
    //}

    try {
      logger.info(format("signing subject '%s' as proof of possession of private key", subject));
      Signature sig;
      if ("EC".equals(privateKey.getAlgorithm())) {
        sig = Signature.getInstance("SHA256withECDSA");
      } else {
        throw new NoSuchAlgorithmException(
            format("unable to generate signature for signing algorithm %s",
                request.signingAlgorithm()));
      }
      sig.initSign(privateKey);
      sig.update(subject.getBytes());
      return newResultFrom(result).signedEmailAddress(base64(sig.sign())).build();
    } catch (Exception e) {
      throw new Exception(format("Error signing '%s': %s", subject, e.getMessage()), e);
    }
  }

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
          format("Error obtaining signing certificate from Fulcio @ %s:",
              request.fulcioInstanceURL()), e);
    }
  }

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

  private SigstoreResult generateArtifactSignature(SigstoreRequest request, SigstoreResult result) throws Exception {
    try {
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
