package io.takari.jpgp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Date;
import java.util.Iterator;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;

public class PgpMessageEncryptor extends PgpSupport {

  private void encryptAndSign(PGPSecretKey pgpSecretKey, String password, String inputDataName, InputStream inputData, OutputStream encryptedDataStream) throws PGPException, IOException {
    PGPSignatureGenerator pgpSignatureGenerator = null;

    PGPPrivateKey signingKey = null;
    if (pgpSecretKey != null) {
      signingKey = findPrivateKey(pgpSecretKey, password);
    }

    PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
    try (OutputStream compressedDataStream = new BCPGOutputStream(compressedDataGenerator.open(encryptedDataStream))) {

      if (signingKey != null) {
        pgpSignatureGenerator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(signingKey.getPublicKeyPacket().getAlgorithm(), HashAlgorithmTags.SHA256));
        pgpSignatureGenerator.init(PGPSignature.BINARY_DOCUMENT, signingKey);
        pgpSignatureGenerator.generateOnePassVersion(false).encode(compressedDataStream);
      }
      PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator(false);
      try (OutputStream literalDataOutputStream = literalDataGenerator.open(compressedDataStream, PGPLiteralDataGenerator.BINARY, inputDataName, new Date(), new byte[4096])) {
        IOUtils.StreamHandler streamHandler = null;
        if (signingKey != null) {
          streamHandler = pgpSignatureGenerator::update;
        }
        IOUtils.copy(inputData, literalDataOutputStream, new byte[4096], streamHandler);
        literalDataGenerator.close();
      }
      if (signingKey != null) {
        pgpSignatureGenerator.generate().encode(compressedDataStream);
      }
      compressedDataGenerator.close();
    }
  }

  protected int getEncryptionAlgorithm() {
    return PGPEncryptedData.AES_256;
  }

  public boolean encrypt(InputStream publicKeyOfRecipient, String inputDataName, InputStream plainInputData, OutputStream target) {
    return encrypt(publicKeyOfRecipient, null, null, null, inputDataName, plainInputData, target);
  }

  public boolean encrypt(InputStream publicKeyOfRecipient, InputStream privateKeyOfSender, String userIdOfSender, String passwordOfSendersPrivateKey, String inputDataName, InputStream plainInputData,
      OutputStream target) {
    boolean result = true;
    PGPPublicKey pgpPublicKey = findPublicKey(publicKeyOfRecipient, pgpKey -> pgpKey.isEncryptionKey() && !pgpKey.isMasterKey());
    if (pgpPublicKey != null) {
      try (OutputStream wrappedTargetStream = new ArmoredOutputStream(target)) {
        BcPGPDataEncryptorBuilder encryptorBuilder = new BcPGPDataEncryptorBuilder(getEncryptionAlgorithm());
        encryptorBuilder.setWithIntegrityPacket(true);
        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(encryptorBuilder);
        encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(pgpPublicKey));
        PGPSecretKey pgpSecretKey = null;
        if (privateKeyOfSender != null) {
          pgpSecretKey = findSecretKey(privateKeyOfSender, userIdOfSender);
        }
        try (OutputStream encryptedDataStream = encryptedDataGenerator.open(wrappedTargetStream, new byte[4096])) {
          encryptAndSign(pgpSecretKey, passwordOfSendersPrivateKey, inputDataName, plainInputData, encryptedDataStream);
        }
      } catch (IOException | PGPException e) {
        result = false;
      }
    } else {
      result = false;
    }
    return result;
  }

  public boolean decrypt(String passwordOfReceiversPrivateKey, InputStream privateKeyOfReceiver, InputStream encryptedData, OutputStream target) {
    return decrypt(passwordOfReceiversPrivateKey, privateKeyOfReceiver, null, encryptedData, target);
  }

  public boolean decrypt(String passwordOfReceiversPrivateKey, InputStream privateKeyOfReceiver, InputStream publicKeyOfSender, InputStream encryptedData, OutputStream target) {
    boolean result = true;
    try {
      PGPPublicKeyRingCollection publicKeyRingCollection = null;
      if (publicKeyOfSender != null) {
        try (InputStream armoredInputStream = new ArmoredInputStream(publicKeyOfSender)) {
          publicKeyRingCollection = new PGPPublicKeyRingCollection(armoredInputStream, new BcKeyFingerprintCalculator());
        }
      }
      try (InputStream in = PGPUtil.getDecoderStream(encryptedData)) {

        PGPObjectFactory objectFactory = new PGPObjectFactory(in, new BcKeyFingerprintCalculator());
        PGPEncryptedDataList dataList;

        Object firstObject = objectFactory.nextObject();
        if (firstObject instanceof PGPEncryptedDataList) {
          dataList = (PGPEncryptedDataList) firstObject;
        } else {
          dataList = (PGPEncryptedDataList) objectFactory.nextObject();
        }

        PGPPrivateKey pgpPrivateKey = null;
        PGPEncryptedData pgpEncryptedData = null;
        Iterator<PGPEncryptedData> iterator = dataList.getEncryptedDataObjects();
        while (pgpPrivateKey == null && iterator.hasNext()) {
          pgpEncryptedData = iterator.next();
          pgpPrivateKey = findPrivateKey(privateKeyOfReceiver, ((PGPPublicKeyEncryptedData) pgpEncryptedData).getKeyID(), passwordOfReceiversPrivateKey);
        }
        PublicKeyDataDecryptorFactory publicKeyDataDecryptorFactory = new BcPublicKeyDataDecryptorFactory(pgpPrivateKey);
        try (InputStream clearText = ((PGPPublicKeyEncryptedData) pgpEncryptedData).getDataStream(publicKeyDataDecryptorFactory)) {
          PGPObjectFactory pgpObjectFactory = new PGPObjectFactory(clearText, new BcKeyFingerprintCalculator());
          Object message;
          PGPCompressedData compressedData;
          PGPOnePassSignatureList onePassSignatureList = null;
          PGPOnePassSignature onePassSignature = null;
          PGPLiteralData literalData;
          PGPSignatureList signatures = null;
          PGPPublicKey pgpPublicKey = null;

          while ((message = pgpObjectFactory.nextObject()) != null) {
            if (message instanceof PGPCompressedData) {
              compressedData = (PGPCompressedData) message;
              pgpObjectFactory = new PGPObjectFactory(compressedData.getDataStream(), new BcKeyFingerprintCalculator());
            }
            if (message instanceof PGPLiteralData) {
              literalData = (PGPLiteralData) message;
              try (InputStream literalDataStream = literalData.getInputStream()) {
                IOUtils.StreamHandler streamHandler = null;
                if (onePassSignature != null) {
                  streamHandler = onePassSignature::update;
                }
                IOUtils.copy(literalDataStream, target, new byte[4096], streamHandler);
              }
            } else if (message instanceof PGPOnePassSignatureList) {
              onePassSignatureList = (PGPOnePassSignatureList) message;
              if (publicKeyOfSender != null) {
                onePassSignature = onePassSignatureList.get(0);
                pgpPublicKey = publicKeyRingCollection.getPublicKey(onePassSignature.getKeyID());
                onePassSignature.init(new BcPGPContentVerifierBuilderProvider(), pgpPublicKey);
              }
            } else if (message instanceof PGPSignatureList) {
              signatures = (PGPSignatureList) message;
            }
          }

          for (int i = 0; onePassSignatureList != null && i < onePassSignatureList.size(); i++) {
            if (pgpPublicKey != null && signatures != null) {
              PGPSignature signature = signatures.get(i);
              if (onePassSignature.verify(signature)) {
                String userId = null;
                Iterator<String> it = pgpPublicKey.getUserIDs();
                while (it.hasNext()) {
                  userId = it.next();
                }
              } else {
                result = false;
              }
            }
          }

          if (pgpEncryptedData.isIntegrityProtected()) {
            if (!pgpEncryptedData.verify()) {
              result = false;
            }
          }
        }
      }
    } catch (IOException | PGPException e) {
      result = false;
    }
    return result;
  }
}
