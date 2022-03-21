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

import static dev.sigstore.plugin.ImmutableSigstoreResult.Builder;
import static dev.sigstore.plugin.ImmutableSigstoreResult.builder;
import static java.lang.String.format;
import static java.nio.file.Paths.get;
import static org.apache.maven.sigstore.model.rekord.Signature.Format.PGP;
import static org.apache.maven.sigstore.model.rekord.Signature.Format.SSH;
import static org.apache.maven.sigstore.model.rekord.Signature.Format.X_509;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.client.http.ByteArrayContent;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpContent;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.apache.v2.ApacheHttpTransport;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Base64;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.impl.client.HttpClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Sign
 */
public class Sign {

  public static final int HTTP_201 = 201;
  private static final Logger LOGGER = LoggerFactory.getLogger(Sign.class);

  private SigstoreRequest request;
  private SigstoreResult result;

  public Sign(SigstoreRequest request) {
    this.request = request;
  }

  public SigstoreResult executeSigstoreFlow() throws Exception {
    SigstoreProcessor processor = new FulcioProcessor();
    if (request.type().equals(X_509)) {
      processor = new FulcioProcessor();
    } else if (request.type().equals(PGP)) {
      processor = new PgpProcessor();
    } else if (request.type().equals(SSH)) {
      processor = new SshProcessor();
    }
    SigstoreResult result = processor.process(request);
    result = submitRecordToRekor(request, result);
    LOGGER.info(format("Created entry in transparency log for JAR @ '%s'", result.rekorEntryUrl()));
    return result;
  }

  /**
   * Submits the signature to a Rekor transparency log
   *
   * @return The URL where the entry in the transparency log can be seen for this signature/key combination
   * @throws Exception If any exception happened during interaction with the Rekor instance
   */
  public SigstoreResult submitRecordToRekor(SigstoreRequest request, SigstoreResult result) throws Exception {
    // Stream the contents and don't place the artifact in memory

    try {
      HttpTransport httpTransport = getHttpTransport(request);
      ObjectMapper m = new ObjectMapper();
      String json = m.writerWithDefaultPrettyPrinter().writeValueAsString(result.rekorRecord());
      System.out.println(json);
      byte[] rekorContent = json.getBytes(StandardCharsets.UTF_8);
      HttpContent rekorJsonContent = new ByteArrayContent(null, rekorContent);
      ByteArrayOutputStream rekorStream = new ByteArrayOutputStream();
      rekorJsonContent.writeTo(rekorStream);
      GenericUrl rekorPostUrl = new GenericUrl(request.rekorInstanceURL() + "/api/v1/log/entries");
      HttpRequest rekorReq =
          httpTransport.createRequestFactory().buildPostRequest(rekorPostUrl, rekorJsonContent);
      rekorReq.getHeaders().set("Accept", "application/json");
      rekorReq.getHeaders().set("Content-Type", "application/json");
      HttpResponse rekorResp = rekorReq.execute();
      if (rekorResp.getStatusCode() != HTTP_201) {
        throw new IOException("bad response from rekor: " + rekorResp.parseAsString());
      }
      URL rekorEntryUrl = new URL(new URL(request.rekorInstanceURL()), rekorResp.getHeaders().getLocation());
      return builder().from(result).rekorEntryUrl(rekorEntryUrl.toExternalForm()).build();
    } catch (Exception e) {
      throw new Exception(format("Error in submitting entry to Rekor @ %s:", request.rekorInstanceURL()), e);
    }
  }

  // -----------------------------------------------------------------------------------------------------------------
  //
  // -----------------------------------------------------------------------------------------------------------------

  public static Builder newResultFrom(SigstoreResult result) {
    return ImmutableSigstoreResult.builder().from(result);
  }

  public static String base64(Path path) throws IOException {
    return Base64.getEncoder().encodeToString(Files.readAllBytes(path));
  }

  public static String base64(byte[] input) {
    return Base64.getEncoder().encodeToString(input);
  }

  public static String base64Mime(byte[] input) {
    return base64Mime(input, 64);
  }

  public static String base64Mime(byte[] input, int length) {
    final String lineSeparator = System.getProperty("line.separator");
    Base64.Encoder encoder = Base64.getMimeEncoder(length, lineSeparator.getBytes());
    return new String(encoder.encode(input));
  }


  public static String sha256(Path path) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] hash = digest.digest(Files.readAllBytes(path));
    StringBuilder hexString = new StringBuilder(2 * hash.length);
    for (int i = 0; i < hash.length; i++) {
      String hex = Integer.toHexString(0xff & hash[i]);
      if (hex.length() == 1) {
        hexString.append('0');
      }
      hexString.append(hex);
    }
    return hexString.toString();
  }

  public static byte[] sha512(byte[] input) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-512");
    return digest.digest(input);
  }

  public static String sha512ToHex(byte[] input) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-512");
    byte[] hash = digest.digest(input);
    StringBuilder hexString = new StringBuilder(2 * hash.length);
    for (int i = 0; i < hash.length; i++) {
      String hex = Integer.toHexString(0xff & hash[i]);
      if (hex.length() == 1) {
        hexString.append('0');
      }
      hexString.append(hex);
    }
    return hexString.toString();
  }


  /**
   * Generates an HTTP Transport according to the requested SSL verification settings
   *
   * @return transport object with SSL verification enabled/disabled per the plugin parameter
   * <code>sslVerification</code>
   */
  public static HttpTransport getHttpTransport(SigstoreRequest request) {
    HttpClientBuilder hcb = ApacheHttpTransport.newDefaultHttpClientBuilder();
    if (!request.sslVerfication()) {
      hcb = hcb.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE);
    }
    return new ApacheHttpTransport(hcb.build());
  }

}
