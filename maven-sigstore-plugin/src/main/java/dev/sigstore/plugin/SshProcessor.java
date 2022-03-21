package dev.sigstore.plugin;

import static dev.sigstore.plugin.Sign.base64;
import static dev.sigstore.plugin.Sign.sha256;
import static java.nio.file.Files.writeString;

import dev.sigstore.plugin.ImmutableSigstoreResult.Builder;
import java.io.FileReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import org.apache.maven.sigstore.ssh.OpenSshSignature;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.util.io.pem.PemReader;
import org.zeroturnaround.exec.ProcessExecutor;

// https://stackoverflow.com/questions/66476780/sign-verify-json-using-ed25519-keys-with-bouncy-castle-java
// https://www.agwa.name/blog/post/ssh_signatures
// https://blog.sigstore.dev/ssh-is-the-new-gpg-74b3c6cc51c0
// https://github.com/sigstore/rekor/blob/main/pkg/pki/ssh/README.md

// install rekor-cli
// make an entry and see if I can see the format of the entry being sent
// ask if there's anything special about the formatting

public class SshProcessor extends SigstoreProcessorSupport {

  @Override
  public SigstoreResult process(SigstoreRequest request) throws Exception {

    Path privateKey = request.sshRequest().privateKey();
    Path publicKey = request.sshRequest().publicKey();

    Builder resultBuilder = ImmutableSigstoreResult.builder();

    Path artifact = request.artifact();

    Path sha256Path = artifact.resolveSibling(artifact.getFileName() + ".sha256");
    String sha256 = sha256(artifact);
    writeString(sha256Path, sha256);

    // Load private key
    AsymmetricKeyParameter privateKeyParameters = null;
    try (Reader fileReader = Files.newBufferedReader(privateKey);
        PemReader pemReader = new PemReader(fileReader)) {
      byte[] privateKeyContent = pemReader.readPemObject().getContent();
      privateKeyParameters = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(privateKeyContent);
    }

    // Load public key, Rekor just consumes the contents of the files and deals with it
    String publicKeyBody = Files.readString(publicKey);

    Path publicKeyPath = artifact.resolveSibling(artifact.getFileName() + ".sshpub");
    String publicKeyContent = base64(publicKeyBody.getBytes(StandardCharsets.UTF_8));
    writeString(publicKeyPath, publicKeyContent);
    resultBuilder.publicKeyContent(publicKeyContent);

    OpenSshSignature sshSignature = new OpenSshSignature(privateKey, publicKey);

    // ssh-keygen -Y sign -n file -f ${HOME}/.ssh/id_ed25519 ${file}
    String output = new ProcessExecutor().command(
            "ssh-keygen", "-Y", "sign", "-n", "file", "-f", "/Users/jvanzyl/.ssh/id_ed25519", artifact.toString())
        .readOutput(true).execute()
        .outputUTF8();

    Path signaturePath = artifact.resolveSibling(artifact.getFileName() + ".sig");
    String signatureContent = Files.readString(signaturePath);
    resultBuilder.artifactSignatureContent(base64(signatureContent.getBytes(StandardCharsets.UTF_8)));
    SigstoreResult result = resultBuilder.build();
    Map<String, Object> rekord = rekord(request, result);
    return ImmutableSigstoreResult.builder().from(result).rekorRecord(rekord).build();
  }
}
