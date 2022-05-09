package dev.sigstore.pgp.passphrase;

import dev.sigstore.pgp.PgpKeyRingLoader;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.util.encoders.Hex;
import org.newsclub.net.unix.AFUNIXSocket;
import org.newsclub.net.unix.AFUNIXSocketAddress;
import org.newsclub.net.unix.AFUNIXSocketException;

public class GpgAgentPassphraseSource implements PassphraseSource {

  private static final File DEFAULT_AGENT_UNIX_SOCKET = new File(new File(System.getProperty("user.home")), ".gnupg/S.gpg-agent");

  public static void main(String[] args) throws Exception {
    PGPSecretKey secretKey = new PgpKeyRingLoader().load();
    String passphrase = new GpgAgentPassphraseSource().load(secretKey, DEFAULT_AGENT_UNIX_SOCKET);
    System.out.println(passphrase);
  }

  public String load(PGPSecretKey secretKey) throws IOException {
    return load(secretKey, DEFAULT_AGENT_UNIX_SOCKET);
  }

  public String load(PGPSecretKey secretKey, File socketFile) throws IOException {
    try (AFUNIXSocket sock = AFUNIXSocket.newInstance()) {
      try {
        sock.connect(new AFUNIXSocketAddress(socketFile));
      } catch (AFUNIXSocketException e) {
        System.out.println("Cannot connect to server. Have you started it?");
        System.out.flush();
        throw e;
      }

      try (
          BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream())); //
          OutputStream os = sock.getOutputStream()) {

        expectOK(in);
        String display = System.getenv("DISPLAY");
        if (display != null) {
          os.write(("OPTION display=" + display + "\n").getBytes());
          os.flush();
          expectOK(in);
        }
        String term = System.getenv("TERM");
        if (term != null) {
          os.write(("OPTION ttytype=" + term + "\n").getBytes());
          os.flush();
          expectOK(in);
        }
        String keyId = Long.toHexString(secretKey.getPublicKey().getKeyID() & 0xFFFFFFFFL);
        // https://unix.stackexchange.com/questions/71135/how-can-i-find-out-what-keys-gpg-agent-has-cached-like-how-ssh-add-l-shows-yo
        String instruction = "GET_PASSPHRASE " + keyId + " " + "Passphrase+incorrect" + " Passphrase Enter%20passphrase%20to%20unlock%20key+" + keyId + "+for+signing+maven+artifact\n";
        os.write((instruction).getBytes());
        os.flush();
        return new String(Hex.decode(expectOK(in).trim()));
      }
    }
  }

  private String expectOK(BufferedReader in) throws IOException {
    String response = in.readLine();
    if (!response.startsWith("OK")) {
      throw new IOException("Expected OK but got this instead: " + response);
    }
    return response.substring(Math.min(response.length(), 3));
  }
}
