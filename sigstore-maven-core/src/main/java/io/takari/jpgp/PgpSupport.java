package io.takari.jpgp;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Iterator;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

public abstract class PgpSupport {

  public static final File DEFAULT_PGP_DIRECTORY = new File(System.getProperty("user.home"), ".gnupg");
  public static final File DEFAULT_PGP_KEYRING = new File(DEFAULT_PGP_DIRECTORY, "secring.gpg");
  public static final File jpgpPrivateKeyFile = new File(DEFAULT_PGP_DIRECTORY, ".jpgp.privatekey");
  public static final File jpgpPassphraseFile = new File(DEFAULT_PGP_DIRECTORY, ".jpgp.passphrase");

  protected PGPSecretKey retrieveSecretKey(PGPSecretKeyRingCollection secretKeyRingCollection, KeyFilter<PGPSecretKey> keyFilter) {
    PGPSecretKey result = null;
    Iterator<PGPSecretKeyRing> secretKeyRingIterator = secretKeyRingCollection.getKeyRings();
    PGPSecretKeyRing secretKeyRing;
    while (result == null && secretKeyRingIterator.hasNext()) {
      secretKeyRing = secretKeyRingIterator.next();
      Iterator<PGPSecretKey> secretKeyIterator = secretKeyRing.getSecretKeys();
      while (secretKeyIterator.hasNext()) {
        PGPSecretKey secretKey = secretKeyIterator.next();
        if (keyFilter.accept(secretKey)) {
          result = secretKey;
        }
      }
    }
    return result;
  }

  protected PGPSecretKey findSecretKey(InputStream secretKey, final String userId) throws IOException, PGPException {
    return findSecretKey(secretKey, secretKey1 -> {
      boolean result = false;
      Iterator<String> userIdIterator = secretKey1.getUserIDs();
      while (userIdIterator.hasNext() && !result) {
        result = userId.equals(userIdIterator.next());
      }
      return result;
    });
  }

  protected PGPSecretKey findSecretKey(InputStream secretKey, KeyFilter<PGPSecretKey> keyFilter) throws IOException, PGPException {
    PGPSecretKey result;
    try (InputStream armoredSecretKey = new ArmoredInputStream(secretKey)) {
      PGPSecretKeyRingCollection keyRingCollection = new PGPSecretKeyRingCollection(armoredSecretKey, new JcaKeyFingerprintCalculator());
      result = retrieveSecretKey(keyRingCollection, keyFilter);
    }
    return result;
  }

  protected PGPPrivateKey findPrivateKey(InputStream secretKey, final long keyId, String password) throws PGPException, IOException {
    return findPrivateKey(secretKey, password, secretKey1 -> secretKey1.getKeyID() == keyId);
  }

  protected PGPPrivateKey findPrivateKey(InputStream secretKey, String password, KeyFilter<PGPSecretKey> keyFilter) throws IOException, PGPException {
    return findPrivateKey(findSecretKey(secretKey, keyFilter), password);
  }

  protected PGPPrivateKey findPrivateKey(PGPSecretKey pgpSecretKey, String password) throws PGPException {
    PGPPrivateKey result;
    PBESecretKeyDecryptor pbeSecretKeyDecryptor = new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().build()).build(password.toCharArray());
    result = pgpSecretKey.extractPrivateKey(pbeSecretKeyDecryptor);
    return result;
  }

  protected PGPPublicKey findPublicKey(InputStream publicKey, KeyFilter<PGPPublicKey> keyFilter) {
    return retrievePublicKey(readPublicKeyRing(publicKey), keyFilter);
  }

  protected PGPPublicKey retrievePublicKey(PGPPublicKeyRing publicKeyRing, KeyFilter<PGPPublicKey> keyFilter) {
    PGPPublicKey result = null;
    Iterator<PGPPublicKey> publicKeyIterator = publicKeyRing.getPublicKeys();
    while (result == null && publicKeyIterator.hasNext()) {
      PGPPublicKey key = publicKeyIterator.next();
      if (keyFilter.accept(key)) {
        result = key;
      }
    }
    return result;
  }

  protected PGPPublicKeyRing readPublicKeyRing(InputStream publicKey) {
    PGPPublicKeyRing result = null;
    try (InputStream decoderStream = PGPUtil.getDecoderStream(publicKey)) {
      PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(decoderStream, new JcaKeyFingerprintCalculator());
      Object o;
      while ((o = pgpObjectFactory.nextObject()) != null && result == null) {
        if (o instanceof PGPPublicKeyRing) {
          result = (PGPPublicKeyRing) o;
        }
      }
    } catch (IOException ignored) {
    }
    return result;
  }

  protected interface KeyFilter<T> {

    boolean accept(T pgpKey);

  }
}
