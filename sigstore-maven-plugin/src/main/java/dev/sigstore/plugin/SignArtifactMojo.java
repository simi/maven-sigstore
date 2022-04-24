package dev.sigstore.plugin;

import static dev.sigstore.ImmutableSigstoreRequest.*;
import static java.lang.String.format;
import static java.nio.file.Files.copy;
import static java.nio.file.Files.createDirectories;

import dev.sigstore.SigstoreSigner;
import dev.sigstore.SigstoreRequest;
import dev.sigstore.SigstoreResult;
import io.takari.jpgp.PgpArtifactSigner;
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

@Mojo(name = "signArtifact", defaultPhase = LifecyclePhase.VERIFY, threadSafe = true)
public class SignArtifactMojo extends AbstractMojo {

  public static final String SIGNATURE_EXTENSION = ".asc";
  private static final Logger logger = LoggerFactory.getLogger(SignArtifactMojo.class);

  @Inject
  protected MavenProjectHelper projectHelper;

  @Parameter(defaultValue = "${project}", readonly = true, required = true)
  private MavenProject project;

  @Parameter(property = "gpg.skip", defaultValue = "false")
  private boolean skip;

  @Parameter(property = "gpg.passphrase")
  private String passphrase;

  // Sigstore

  /** Signing algorithm to be used; default is ECDSA */
  @Parameter( defaultValue = "sigstore", property = "signer-name", required = true )
  private String signerName;

  /** Signing algorithm to be used; default is ECDSA */
  @Parameter( defaultValue = "EC", property = "signing-algorithm", required = true )
  private String signingAlgorithm;

  /** Signing algorithm specification to be used; default is secp256r1 */
  @Parameter( defaultValue = "secp256r1", property = "signing-algorithm-spec", required = true )
  private String signingAlgorithmSpec;

  /** URL of Fulcio instance */
  @Parameter( defaultValue = "https://fulcio.sigstore.dev", property = "fulcio-instance-url", required = true )
  private URL fulcioInstanceURL;

  /** Use browser-less OAuth Device Code flow instead of opening local browser */
  @Parameter( defaultValue = "false", property = "oidc-device-code", required = true )
  private boolean oidcDeviceCodeFlow;

  /** Client ID for OIDC Identity Provider */
  @Parameter( defaultValue = "sigstore", property = "oidc-client-id", required = true )
  private String oidcClientID;

  /** URL of OIDC Identity Provider Authorization endpoint */
  @Parameter( defaultValue = "https://oauth2.sigstore.dev/auth/auth", property = "oidc-auth-url", required = true )
  private URL oidcAuthURL;

  /** URL of OIDC Identity Provider Token endpoint */
  @Parameter( defaultValue = "https://oauth2.sigstore.dev/auth/token", property = "oidc-token-url", required = true )
  private URL oidcTokenURL;

  /** URL of OIDC Identity Provider Device Code endpoint */
  @Parameter( defaultValue = "https://oauth2.sigstore.dev/auth/device/code", property = "oidc-device-code-url", required = true )
  private URL oidcDeviceCodeURL;

  /** URL of Rekor instance */
  @Parameter( defaultValue = "https://rekor.sigstore.dev", property = "rekor-instance-url", required = true )
  private URL rekorInstanceURL;

  /** Email address of signer; if not specified, the email address returned in the OIDC identity token will be used */
  @Parameter( property = "email-address" )
  private String emailAddress;

  /** URL of Trusted Timestamp Authority (RFC3161 compliant) */
  @Parameter( defaultValue = "https://rekor.sigstore.dev/api/v1/timestamp", property = "tsa-url", required = true )
  private URL tsaURL;

  @Override
  public void execute() throws MojoExecutionException {
    List<SigningBundle> signingBundles = new ArrayList<>();

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
      File projectArtifactSignature = sign(file);
      if (projectArtifactSignature != null) {
        signingBundles.add(new SigningBundle(artifact.getArtifactHandler().getExtension(), projectArtifactSignature));
      }
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
    File pomSignature = sign(pomToSign);
    if (pomSignature != null) {
      signingBundles.add(new SigningBundle("pom", pomSignature));
    }

    //
    // Attached artifact signatures
    //
    for (org.apache.maven.artifact.Artifact a : project.getAttachedArtifacts()) {
      File signatureFile = sign(a.getFile());
      if (signatureFile != null) {
        signingBundles.add(new SigningBundle(a.getArtifactHandler().getExtension(), signatureFile, a.getClassifier()));
      }
    }

    for (SigningBundle bundle : signingBundles) {
      projectHelper.attachArtifact(project, bundle.getExtension() + SIGNATURE_EXTENSION, bundle.getClassifier(), bundle.getSignature());
    }
  }

  private File sign(File file) throws MojoExecutionException {
    SigstoreRequest request = builder().build();

    try {
      SigstoreResult result = new SigstoreSigner(request).executeSigstoreFlow();
      logger.info(format("Created entry in transparency log for JAR @ '%s'", result.rekorEntryUrl()));
    } catch(Exception e) {
      throw new MojoExecutionException(e);
    }

    try {
      PgpArtifactSigner signer = new PgpArtifactSigner();
      if (passphrase != null) {
        return signer.sign(file, passphrase);
      } else {
        return signer.sign(file);
      }
    } catch (Exception e) {
      throw new MojoExecutionException("Error signing artifact " + file + ".", e);
    }
  }
}
