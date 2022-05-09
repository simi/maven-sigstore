package dev.sigstore.plugin;

import static dev.sigstore.ImmutableSigstoreRequest.builder;
import static dev.sigstore.SigstoreRequest.Type.X_509;
import static java.nio.file.Files.copy;
import static java.nio.file.Files.createDirectories;

import dev.sigstore.SigstoreRequest;
import dev.sigstore.SigstoreResult;
import dev.sigstore.SigstoreSigner;
import dev.sigstore.pgp.PgpArtifactSigner;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;
import javax.inject.Inject;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.MavenProjectHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Mojo(name = "sign", defaultPhase = LifecyclePhase.VERIFY, threadSafe = true)
public class SignMojo extends AbstractMojo {

  public static final String PGP_SIGNATURE_EXTENSION = ".asc";
  public static final String X509_SIGNATURE_EXTENSION = ".sig";
  public static final String X509_CERTIFICATE_EXTENSION = ".pem";

  private static final Logger logger = LoggerFactory.getLogger(SignMojo.class);

  @Inject
  protected MavenProjectHelper projectHelper;

  @Parameter(defaultValue = "${project}", readonly = true, required = true)
  private MavenProject project;

  // ---------------------------------------------------------------------------
  // Modes
  // ---------------------------------------------------------------------------
  //
  // sigstore x509 signatures
  // maven pgp signatures with sigstore x509 signatures
  // maven pgp signatures with sigstore PGP signatures
  //

  // ---------------------------------------------------------------------------
  // PGP
  // ---------------------------------------------------------------------------

  @Parameter(property = "pgpEnable")
  private boolean pgpEnabled;

  @Parameter(property = "pgpPassphrase")
  private String pgpPassphrase;

  // ---------------------------------------------------------------------------
  // Sigstore
  // ---------------------------------------------------------------------------

  /**
   * Signing algorithm to be used; default is ECDSA
   */
  @Parameter(defaultValue = "sigstore", property = "signer-name", required = true)
  private String signerName;

  /**
   * Signing algorithm to be used; default is ECDSA
   */
  @Parameter(defaultValue = "EC", property = "signing-algorithm", required = true)
  private String signingAlgorithm;

  /**
   * Signing algorithm specification to be used; default is secp256r1
   */
  @Parameter(defaultValue = "secp256r1", property = "signing-algorithm-spec", required = true)
  private String signingAlgorithmSpec;

  /**
   * URL of Fulcio instance
   */
  @Parameter(defaultValue = "https://fulcio.sigstore.dev", property = "fulcio-instance-url", required = true)
  private URL fulcioInstanceURL;

  /**
   * Use browser-less OAuth Device Code flow instead of opening local browser
   */
  @Parameter(defaultValue = "false", property = "oidc-device-code", required = true)
  private boolean oidcDeviceCodeFlow;

  /**
   * Client ID for OIDC Identity Provider
   */
  @Parameter(defaultValue = "sigstore", property = "oidc-client-id", required = true)
  private String oidcClientID;

  /**
   * URL of OIDC Identity Provider Authorization endpoint
   */
  @Parameter(defaultValue = "https://oauth2.sigstore.dev/auth/auth", property = "oidc-auth-url", required = true)
  private URL oidcAuthURL;

  /**
   * URL of OIDC Identity Provider Token endpoint
   */
  @Parameter(defaultValue = "https://oauth2.sigstore.dev/auth/token", property = "oidc-token-url", required = true)
  private URL oidcTokenURL;

  /**
   * URL of OIDC Identity Provider Device Code endpoint
   */
  @Parameter(defaultValue = "https://oauth2.sigstore.dev/auth/device/code", property = "oidc-device-code-url", required = true)
  private URL oidcDeviceCodeURL;

  /**
   * URL of Rekor instance
   */
  @Parameter(defaultValue = "https://rekor.sigstore.dev", property = "rekor-instance-url", required = true)
  private URL rekorInstanceURL;

  /**
   * Email address of signer; if not specified, the email address returned in the OIDC identity token will be used
   */
  @Parameter(property = "email-address")
  private String emailAddress;

  /**
   * URL of Trusted Timestamp Authority (RFC3161 compliant)
   */
  @Parameter(defaultValue = "https://rekor.sigstore.dev/api/v1/timestamp", property = "tsa-url", required = true)
  private URL tsaURL;

  @Override
  public void execute() throws MojoExecutionException {
    List<SignedBlob> signedBlobs = new ArrayList<>();

    if (!"pom".equals(project.getPackaging())) {
      //
      // Artifact
      //
      org.apache.maven.artifact.Artifact artifact = project.getArtifact();
      File file = artifact.getFile();
      if (file == null) {
        logger.info("There is no artifact present. Make sure you run this after the package phase.");
        return;
      }
      signedBlobs.add(new SignedBlob(file.toPath(), artifact.getArtifactHandler().getExtension()));
    }

    //
    // POM
    //
    File pomToSign = new File(project.getBuild().getDirectory(), project.getBuild().getFinalName() + ".pom");
    try {
      createDirectories(pomToSign.getParentFile().toPath());
      copy(project.getFile().toPath(), pomToSign.toPath(), StandardCopyOption.REPLACE_EXISTING);
    } catch (IOException e) {
      throw new MojoExecutionException("Error copying POM for signing.", e);
    }
    signedBlobs.add(new SignedBlob(pomToSign.toPath(), "pom"));

    //
    // Attached artifacts
    //
    for (org.apache.maven.artifact.Artifact a : project.getAttachedArtifacts()) {
      signedBlobs.add(new SignedBlob(a.getFile().toPath(), a.getArtifactHandler().getExtension(), a.getClassifier()));
    }

    for (SignedBlob blob : signedBlobs) {
      File file = blob.blob().toFile();
      try {
        SigstoreRequest request = builder()
            .artifact(file.toPath())
            .type(X_509)
            .emailAddress("jason@vanzyl.ca")
            .build();
        SigstoreResult result = new SigstoreSigner(request).sign();
        projectHelper.attachArtifact(project, blob.extension() + X509_SIGNATURE_EXTENSION, blob.classifier(), result.artifactSignature().toFile());
        projectHelper.attachArtifact(project, blob.extension() + X509_CERTIFICATE_EXTENSION, blob.classifier(), result.signingCertificate().toFile());
      } catch (Exception e) {
        throw new MojoExecutionException(e);
      }

      if (pgpEnabled) {
        try {
          PgpArtifactSigner signer = new PgpArtifactSigner();
          File pgpSignature = signer.sign(file, pgpPassphrase);
          projectHelper.attachArtifact(project, blob.extension() + PGP_SIGNATURE_EXTENSION, blob.classifier(), pgpSignature);
        } catch (Exception e) {
          throw new MojoExecutionException("Error signing artifact " + file + ".", e);
        }
      }
    }
  }
}
