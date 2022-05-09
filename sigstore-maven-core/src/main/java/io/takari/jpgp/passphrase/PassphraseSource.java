package io.takari.jpgp.passphrase;

import java.io.IOException;
import org.bouncycastle.openpgp.PGPSecretKey;

public interface PassphraseSource {

  String load(PGPSecretKey secretKey) throws IOException;
}
