package dev.sigstore.pgp;

import java.io.OutputStream;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

public class PgpKeyPairGenerator {

  public static final int DEFAULT_KEYSIZE = 4096;
  private static final String SECURITY_PROVIDER = "BC";
  int[] preferredEncryptionAlgorithms = new int[]{
      SymmetricKeyAlgorithmTags.AES_256,
      SymmetricKeyAlgorithmTags.AES_192,
      SymmetricKeyAlgorithmTags.AES_128
  };
  int[] preferredHashAlgorithms = new int[]{
      HashAlgorithmTags.SHA512,
      HashAlgorithmTags.SHA384,
      HashAlgorithmTags.SHA256
  };

  // https://github.com/bcgit/bc-java/wiki/OpenPGP-Questions

  // Standard components
  int[] preferredCompressionAlgorithms = new int[]{
      CompressionAlgorithmTags.ZIP,
      CompressionAlgorithmTags.BZIP2,
      CompressionAlgorithmTags.ZLIB,
      CompressionAlgorithmTags.UNCOMPRESSED
  };

  private PGPContentSignerBuilder contentSignerBuilder(PGPKeyPair pgpKeyPair) {
    return new JcaPGPContentSignerBuilder(pgpKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256);
  }

  private KeyPairGenerator keyPairGenerator() throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    return KeyPairGenerator.getInstance("RSA", SECURITY_PROVIDER);
  }

  private PGPDigestCalculatorProvider digestCalculatorProvider() throws Exception {
    return new JcaPGPDigestCalculatorProviderBuilder()
        .setProvider(SECURITY_PROVIDER)
        .build();
  }

  private PGPDigestCalculator digestCalculator() throws Exception {
    return digestCalculatorProvider().get(HashAlgorithmTags.SHA1);
  }

  private PBESecretKeyEncryptor secretKeyEncryptor(PGPKeyPair keyPair, String passphrase) throws Exception {
    return new JcePBESecretKeyEncryptorBuilder(keyPair.getPublicKey().getAlgorithm(), digestCalculator())
        .setProvider(SECURITY_PROVIDER)
        .build(passphrase.toCharArray());
  }

  private PBESecretKeyDecryptor secretKeyDecryptor(String passphrase) throws Exception {
    return new JcePBESecretKeyDecryptorBuilder(digestCalculatorProvider())
        .setProvider(SECURITY_PROVIDER)
        .build(passphrase.toCharArray());
  }

  // RFC 4880 - 13.5: Don't set any type of RSA like sign-only/encrypt-only on the keypair itself as this is deprecated,
  // but instead use the keyflags subpacket in a signature to indicate what you want the keypair to do.

  public PGPKeyPair generateKeyPair() {
    return generateKeyPair(DEFAULT_KEYSIZE);
  }

  public PGPKeyPair generateKeyPair(int keySize) {
    PGPKeyPair pgpKeyPair;
    try {
      KeyPairGenerator keyPairGenerator = keyPairGenerator();
      keyPairGenerator.initialize(keySize);
      pgpKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, keyPairGenerator.generateKeyPair(), new Date());
    } catch (Exception e) {
      pgpKeyPair = null;
    }
    return pgpKeyPair;
  }

  // Creating a secret key ring from scratch
  public PGPSecretKeyRing secretKeyRing(String userId, String passphrase) throws Exception {
    PGPKeyPair pgpKeyPair = generateKeyPair(DEFAULT_KEYSIZE);
    PGPContentSignerBuilder signer = contentSignerBuilder(pgpKeyPair);
    //PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(signer);
    PGPSignatureSubpacketGenerator primarySubpacketGenerator = new PGPSignatureSubpacketGenerator();
    primarySubpacketGenerator.setPrimaryUserID(false, true);
    primarySubpacketGenerator.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER);
    //primarySubpacketGenerator.setPreferredSymmetricAlgorithms(false, preferredEncryptionAlgorithms);
    //primarySubpacketGenerator.setPreferredHashAlgorithms(false, preferredHashAlgorithms);
    //primarySubpacketGenerator.setPreferredCompressionAlgorithms(false, preferredCompressionAlgorithms);

    LocalDate e = LocalDate.now().plusYears(1);
    Date expirationDate = Date.from(e.atStartOfDay(ZoneId.systemDefault()).toInstant());
    long secondsToExpire = SignatureSubpacketGeneratorUtil.getKeyLifetimeInSeconds(expirationDate, new Date());
    if (expirationDate != null) {
      SignatureSubpacketGeneratorUtil.setExpirationDateInSubpacketGenerator(secondsToExpire, primarySubpacketGenerator);
    }

    PGPKeyRingGenerator ringGenerator = new PGPKeyRingGenerator(
        PGPSignature.POSITIVE_CERTIFICATION,
        pgpKeyPair,
        userId,
        digestCalculator(),
        primarySubpacketGenerator.generate(),
        null,
        signer,
        secretKeyEncryptor(pgpKeyPair, passphrase));

    // Definitely having a builder would be better

    PGPSignatureSubpacketGenerator encryptionSubpacketGenerator = new PGPSignatureSubpacketGenerator();
    encryptionSubpacketGenerator.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
    SignatureSubpacketGeneratorUtil.setExpirationDateInSubpacketGenerator(secondsToExpire, encryptionSubpacketGenerator);

    PGPKeyPair encryptionKeyPair = generateKeyPair();
    ringGenerator.addSubKey(encryptionKeyPair, encryptionSubpacketGenerator.generate(), null);

    PGPSignatureSubpacketGenerator signingSubpacketGenerator = new PGPSignatureSubpacketGenerator();
    signingSubpacketGenerator.setKeyFlags(false, KeyFlags.SIGN_DATA);
    SignatureSubpacketGeneratorUtil.setExpirationDateInSubpacketGenerator(secondsToExpire, signingSubpacketGenerator);
    PGPKeyPair signingKeyPair = generateKeyPair();
    ringGenerator.addSubKey(signingKeyPair, signingSubpacketGenerator.generate(), null);

    PGPSignatureSubpacketGenerator authSubpacketGenerator = new PGPSignatureSubpacketGenerator();
    authSubpacketGenerator.setKeyFlags(false, KeyFlags.AUTHENTICATION);
    SignatureSubpacketGeneratorUtil.setExpirationDateInSubpacketGenerator(secondsToExpire, authSubpacketGenerator);
    PGPKeyPair authKeyPair = generateKeyPair();
    ringGenerator.addSubKey(authKeyPair, authSubpacketGenerator.generate(), null);

    return ringGenerator.generateSecretKeyRing();
  }

  // This assumes you've already unlocked the keyring
  public void exportKeyRing(OutputStream secretOut, PGPSecretKeyRing keyRing) throws Exception {
    try (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(secretOut)) {
      keyRing.encode(armoredOutputStream);
    }
  }

  public void exportPrivateKey(OutputStream stream, PGPKeyPair pgpKeyPair, String user, String passphrase) throws Exception {
    PGPSecretKey secretKey = new PGPSecretKey(
        PGPSignature.POSITIVE_CERTIFICATION,
        pgpKeyPair,
        user,
        digestCalculator(),
        null,
        null,
        contentSignerBuilder(pgpKeyPair),
        secretKeyEncryptor(pgpKeyPair, passphrase));

    try (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(stream)) {
      secretKey.encode(armoredOutputStream);
    }
  }

  public void exportPublicKey(OutputStream stream, PGPKeyPair pgpKeyPair) throws Exception {
    PGPPublicKey publicKey = pgpKeyPair.getPublicKey();
    try (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(stream)) {
      publicKey.encode(armoredOutputStream);
    }
  }
}
