package org.apache.maven.sigstore.ssh;

import static dev.sigstore.plugin.Sign.base64;
import static dev.sigstore.plugin.Sign.base64Mime;
import static dev.sigstore.plugin.Sign.sha512;
import static java.lang.String.format;
import static java.nio.file.Files.newBufferedReader;
import static java.nio.file.Files.newBufferedWriter;
import static java.nio.file.Files.readString;
import static java.nio.file.Paths.get;
import static java.util.Base64.getDecoder;
import static org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil.parsePrivateKeyBlob;
import static org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil.encodePublicKey;
import static org.bouncycastle.crypto.util.OpenSSHPublicKeyUtil.parsePublicKey;

import com.jcraft.jsch.bc.SignatureEd25519;
import com.jcraft.jsch.jce.SHA512;
import dev.sigstore.plugin.Sign;
import java.io.ByteArrayOutputStream;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig
// https://github.com/sigstore/rekor/blob/main/pkg/pki/ssh/README.md
// https://github.com/sigstore/rekor/blob/main/types.md#ssh
// https://stackoverflow.com/questions/66476780/sign-verify-json-using-ed25519-keys-with-bouncy-castle-java
// https://www.agwa.name/blog/post/ssh_signatures
// https://blog.sigstore.dev/ssh-is-the-new-gpg-74b3c6cc51c0

public class OpenSshSignature {

  private final Path publicKey;
  private final Path privateKey;

  public OpenSshSignature(Path privateKey, Path publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  // byte[6]   MAGIC_PREAMBLE
  // uint32    SIG_VERSION
  // string    publickey
  // string    namespace
  // string    reserved
  // string    hash_algorithm
  // string    signature
  //
  // MAGIC      S   S   H   S   I   G
  // VERSION   \0  \0  \0 001
  // PUB KEY
  //  fields?  \0  \0  \0   3
  //  kind     \0  \0  \0  \v   s   s   h   -   e   d   2   5   5   1   9
  //  key      \0  \0  \0   x   | 214 365 265 365 375   P   ϣ  **   \ 346 325   y 254 c 306   1   H   ? 236   =   P 221  \n 222 021 025   L 364 110 H
  // * file *  \0  \0  \0 004   f   i   l   e
  // RESVED    \0  \0  \0  \0
  // HASH ALG  \0  \0  \0 006   s   h   a   5   1   2
  // SIG       \0  \0  \0   S
  //           \0  \0  \0  \v   s   s   h   -   e   d   2   5   5   1   9  \0  \0  \0   @   Ɍ
  //           ** 032   Q   /   q 301 350 316   { 001 261 340   y   , 372 021 021 260   U   N
  //          343   e 247 353   P 213   L   K   P 334   |   x 273 026 316   e   n 241 226   u
  //            | 034   g 020 314   } 233   ^ 016   g   %   k 216   u 255 352 322   y 232 317
  //          356  \b

  public void sign(Path input) throws Exception {
    sign(Files.readAllBytes(input));
  }

  public void sign(byte[] input) throws Exception {

    SignatureEd25519 jsig;

    // Load private key
    AsymmetricKeyParameter privateKeyParameters;
    try (Reader reader = newBufferedReader(privateKey); PemReader pemReader = new PemReader(reader)) {
      byte[] privateKeyContent = pemReader.readPemObject().getContent();
      privateKeyParameters = parsePrivateKeyBlob(privateKeyContent);

      jsig = new SignatureEd25519();
      jsig.init();
      jsig.setPrvKey(privateKeyContent);
    }

    //System.out.println(privateKeyParameters.getClass());

    // Load public key
    String publicKeyContent = readString(publicKey);
    String publicKeyType = publicKeyContent.split(" ")[0];
    String publicKeyBody = publicKeyContent.split(" ")[1];
    AsymmetricKeyParameter publicKeyParameters = parsePublicKey(getDecoder().decode(publicKeyBody));
    byte[] encodedPublicKey = encodePublicKey(publicKeyParameters);

    //System.out.println("publicKeyType = " + publicKeyType);
    //System.out.println("publicKeyBody = " + publicKeyBody);

    // #define   MAGIC_PREAMBLE "SSHSIG"
    // #define   SIG_VERSION    0x01
    //
    // byte[6]   MAGIC_PREAMBLE
    // uint32    SIG_VERSION
    // string    publickey
    // string    namespace
    // string    reserved
    // string    hash_algorithm
    // string    signature

    ByteArrayOutputStream signatureBlob = new ByteArrayOutputStream();
    // magic
    signatureBlob.write("SSHSIG".getBytes());
    // version
    byte[] version = new byte[4];
    version[3] = '\001';
    signatureBlob.write(version);
    // publickey
    byte[] fields = new byte[4];
    fields[3] = '3';
    signatureBlob.write(fields);
    signatureBlob.write(encodedPublicKey);
    // namespace: file
    byte[] file = new byte[4];
    file[3] = '\004';
    signatureBlob.write(file);
    signatureBlob.write("file".getBytes());
    // reserved
    signatureBlob.write(new byte[4]);
    // hash algorithm
    byte[] algo = new byte[4];
    algo[3] = '\006';
    signatureBlob.write(algo);
    signatureBlob.write("sha512".getBytes());
    // signature
    byte[] sig = new byte[4];
    sig[3] = 'S';
    signatureBlob.write(sig);
    byte[] v = new byte[4];
    v[3] = 0x000b;
    signatureBlob.write(v);
    signatureBlob.write("ssh-ed25519".getBytes());
    byte[] at = new byte[4];
    at[3] = '@';
    signatureBlob.write(at);

    // Up to here we are identical to ssh-keygen

    // #define   MAGIC_PREAMBLE "SSHSIG"
    //
    // byte[6]   MAGIC_PREAMBLE
    // string    namespace
    // string    reserved
    // string    hash_algorithm
    // string    H(message)

    ByteArrayOutputStream s = new ByteArrayOutputStream();
    // magic
    s.write("SSHSIG".getBytes());
    byte[] a = new byte[4]; a[3] = '\004'; // EOT
    s.write(a);
    // namespace
    s.write("file".getBytes());
    byte[] b = new byte[8]; b[7] = '\006'; // ACK
    s.write(b);
    // reserved
    //s.write(new byte[4]);
    // hash algo
    s.write("sha512".getBytes());
    s.write(at);
    // Is this hashed or not?
    s.write(sha512(input));
    //s.write(input);

    // Is there a signing algo that works for ssh?

    byte[] signatureContent = s.toByteArray();

    // Are the ssh signers different? They appear to produce different output ... they appear
    // to use the same code, what's the diff? SSH expects different encoding

    Signer signer;
    Signer verifier;
    if (publicKeyType.equals("ssh-ed25519")) {
      signer = new Ed25519Signer();
      verifier = new Ed25519Signer();
    } else if (publicKeyType.equals("ssh-rsa")) {
      signer = new RSADigestSigner(new SHA512Digest());
      verifier = new Ed25519Signer();
    } else {
      throw new RuntimeException("Unsupported public key type: " + publicKeyType);
    }

    signer.init(true, privateKeyParameters);
    signer.update(signatureContent, 0, signatureContent.length);
    byte[] signature = signer.generateSignature();

    System.out.println(base64(signature));

    //System.out.println(signature[1]);


    //jsig.update(signatureContent);
    //byte[] signature = jsig.sign();

    // Hash the message
    //byte[] hash = sha512(input);
    //System.out.println(base64(hash));
    //jsig.update(hash);
    //byte[] signedHashOfInput = jsig.sign();

    // Verify
    //verifier.init(false, publicKeyParameters);
    //verifier.update(signatureContent, 0, signatureContent.length);
    //boolean verified = verifier.verifySignature(signature);
    //System.out.println("verified: " + verified);

    // Add signature to signatureBlob
    signatureBlob.write(signature);

    String header = "-----BEGIN SSH SIGNATURE-----";
    String footer = "-----END SSH SIGNATURE-----";
    
    /*
    StringBuilder sb = new StringBuilder();
    String mime = base64(signatureBlob.toByteArray());
    // spec says 76 but it appears to be 70?
    int blockSize = 70;
    for(int i = 0; i < mime.length(); i+=blockSize) {
      String segment;
      if((i + blockSize) > mime.length()) {
        segment = mime.substring(i);
        sb.append(segment);
      } else {
        segment = mime.substring(i, i + blockSize);
        sb.append(segment).append('\n');
      }
    }
     */

    String sb = base64Mime(signatureBlob.toByteArray());

    //System.out.println(sb);

    Files.writeString(get("/Users/jvanzyl/js/security/jssh/roundtrip0/file.txt.sig2"), format("%s%n%s%n%s", header, sb, footer));
    Files.writeString(get("/Users/jvanzyl/js/security/jssh/roundtrip0/file.txt.sig2n"), sb);
    //System.out.println(Sign.base64(os.toByteArray()));


  }

  public static void main(String[] args) throws Exception {
    new OpenSshSignature(
        get("/Users/jvanzyl/js/security/jssh/roundtrip0/id_ed25519"),
        get("/Users/jvanzyl/js/security/jssh/roundtrip0/id_ed25519.pub"))
        .sign(get("/Users/jvanzyl/js/security/jssh/roundtrip0/file.txt"));
  }
}
