package common;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class CryptoService {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private static final SecureRandom RANDOM = new SecureRandom();
    public static final int AEAD_NONCE_LENGTH = 12; // 96 bits standard nonce
    public static final int GCM_TAG_LENGTH = 128;   // 128 bits tag

    public static byte[] encrypt(byte[] plaintext, CryptoConfig config) throws Exception {
        return encrypt(plaintext, null, config);
    }

    public static byte[] encrypt(byte[] plaintext, byte[] aad, CryptoConfig config) throws Exception {
        if (config.isAead()) {
            return encryptAead(plaintext, aad, config);
        } else {
            return encryptClassic(plaintext, config);
        }
    }

    public static byte[] decrypt(byte[] encryptedData, CryptoConfig config) throws Exception {
        return decrypt(encryptedData, null, config);
    }

    public static byte[] decrypt(byte[] encryptedData, byte[] aad, CryptoConfig config) throws Exception {
        if (config.isAead()) {
            return decryptAead(encryptedData, aad, config);
        } else {
            return decryptClassic(encryptedData, config);
        }
    }

    // AEAD Modes (AES/GCM, ChaCha20-Poly1305, AES/CCM, RC6/GCM)
    private static byte[] encryptAead(byte[] plaintext, byte[] aad, CryptoConfig config) throws Exception {
        byte[] nonce = generateNonce(AEAD_NONCE_LENGTH);
        Cipher cipher = Cipher.getInstance(config.getTransformation());

        if ("GCM".equalsIgnoreCase(config.getMode())) {
            cipher.init(Cipher.ENCRYPT_MODE, config.getSecretKey(), new GCMParameterSpec(GCM_TAG_LENGTH, nonce));
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, config.getSecretKey(), new IvParameterSpec(nonce));
        }

        if (aad != null && aad.length > 0) {
            cipher.updateAAD(aad);
        }

        byte[] ciphertext = cipher.doFinal(plaintext);

        ByteBuffer bb = ByteBuffer.allocate(nonce.length + ciphertext.length);
        bb.put(nonce);
        bb.put(ciphertext);
        return bb.array();
    }

    private static byte[] decryptAead(byte[] encryptedData, byte[] aad, CryptoConfig config) throws Exception {
        if (encryptedData.length < AEAD_NONCE_LENGTH) {
            throw new IllegalArgumentException("Encrypted payload shorter than nonce length.");
        }

        byte[] nonce = Arrays.copyOfRange(encryptedData, 0, AEAD_NONCE_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, AEAD_NONCE_LENGTH, encryptedData.length);

        Cipher cipher = Cipher.getInstance(config.getTransformation());
        if ("GCM".equalsIgnoreCase(config.getMode())) {
            cipher.init(Cipher.DECRYPT_MODE, config.getSecretKey(), new GCMParameterSpec(GCM_TAG_LENGTH, nonce));
        } else {
            cipher.init(Cipher.DECRYPT_MODE, config.getSecretKey(), new IvParameterSpec(nonce));
        }

        if (aad != null && aad.length > 0) {
            cipher.updateAAD(aad);
        }

        return cipher.doFinal(ciphertext);
    }

    // Classic Modes (CBC, CTR, ECB, ChaCha20 standalone) + Encrypt-then-MAC
    private static byte[] encryptClassic(byte[] plaintext, CryptoConfig config) throws Exception {
        boolean isEcb = "ECB".equalsIgnoreCase(config.getMode());
        boolean isChaCha = "ChaCha20".equalsIgnoreCase(config.getAlgorithm()) 
            && (config.getMode() == null || "NULL".equalsIgnoreCase(config.getMode()) || "None".equalsIgnoreCase(config.getMode()));
        boolean hasMac = config.getMacAlgorithm() != null && !config.getMacAlgorithm().equalsIgnoreCase("NULL");

        byte[] iv = null;
        Cipher cipher;

        if (isChaCha) {
            cipher = Cipher.getInstance("ChaCha20");
            iv = generateNonce(12);
            cipher.init(Cipher.ENCRYPT_MODE, config.getSecretKey(), new ChaCha20ParameterSpec(iv, 1));
        } else if (isEcb) {
            cipher = Cipher.getInstance(config.getTransformation());
            cipher.init(Cipher.ENCRYPT_MODE, config.getSecretKey());
        } else {
            cipher = Cipher.getInstance(config.getTransformation());
            int ivSize = (config.getIvSize() > 0) ? (config.getIvSize() / 8) : 16;
            iv = generateNonce(ivSize);
            cipher.init(Cipher.ENCRYPT_MODE, config.getSecretKey(), new IvParameterSpec(iv));
        }

        byte[] ciphertext = cipher.doFinal(plaintext);

        if (hasMac) {
            Mac mac = Mac.getInstance(config.getMacAlgorithm());
            mac.init(config.getMacKey());
            if (iv != null) {
                mac.update(iv);
            }
            byte[] hmacTag = mac.doFinal(ciphertext);

            int totalSize = (iv != null ? iv.length : 0) + ciphertext.length + hmacTag.length;
            ByteBuffer bb = ByteBuffer.allocate(totalSize);
            if (iv != null) bb.put(iv);
            bb.put(ciphertext);
            bb.put(hmacTag);
            return bb.array();
        } else {
            int totalSize = (iv != null ? iv.length : 0) + ciphertext.length;
            ByteBuffer bb = ByteBuffer.allocate(totalSize);
            if (iv != null) bb.put(iv);
            bb.put(ciphertext);
            return bb.array();
        }
    }

    private static byte[] decryptClassic(byte[] encryptedData, CryptoConfig config) throws Exception {
        boolean isEcb = "ECB".equalsIgnoreCase(config.getMode());
        boolean isChaCha = "ChaCha20".equalsIgnoreCase(config.getAlgorithm()) 
            && (config.getMode() == null || "NULL".equalsIgnoreCase(config.getMode()) || "None".equalsIgnoreCase(config.getMode()));
        boolean hasMac = config.getMacAlgorithm() != null && !config.getMacAlgorithm().equalsIgnoreCase("NULL");

        int ivSize = isEcb ? 0 : (isChaCha ? 12 : ((config.getIvSize() > 0) ? (config.getIvSize() / 8) : 16));
        int macSize = 0;

        if (hasMac) {
            Mac testMac = Mac.getInstance(config.getMacAlgorithm());
            macSize = testMac.getMacLength();
        }

        if (encryptedData.length < ivSize + macSize) {
            throw new IllegalArgumentException("Encrypted payload truncated or invalid.");
        }

        byte[] iv = isEcb ? null : Arrays.copyOfRange(encryptedData, 0, ivSize);
        int ciphertextEnd = encryptedData.length - macSize;
        byte[] ciphertext = Arrays.copyOfRange(encryptedData, ivSize, ciphertextEnd);

        if (hasMac) {
            byte[] receivedMac = Arrays.copyOfRange(encryptedData, ciphertextEnd, encryptedData.length);
            Mac mac = Mac.getInstance(config.getMacAlgorithm());
            mac.init(config.getMacKey());
            if (iv != null) {
                mac.update(iv);
            }
            byte[] expectedMac = mac.doFinal(ciphertext);

            if (!MessageDigest.isEqual(expectedMac, receivedMac)) {
                throw new SecurityException("Integrity check failed: invalid HMAC! Message has been tampered with.");
            }
        }

        Cipher cipher;
        if (isChaCha) {
            cipher = Cipher.getInstance("ChaCha20");
            cipher.init(Cipher.DECRYPT_MODE, config.getSecretKey(), new ChaCha20ParameterSpec(iv, 1));
        } else if (isEcb) {
            cipher = Cipher.getInstance(config.getTransformation());
            cipher.init(Cipher.DECRYPT_MODE, config.getSecretKey());
        } else {
            cipher = Cipher.getInstance(config.getTransformation());
            cipher.init(Cipher.DECRYPT_MODE, config.getSecretKey(), new IvParameterSpec(iv));
        }

        return cipher.doFinal(ciphertext);
    }

    public static byte[] generateNonce(int length) {
        byte[] nonce = new byte[length];
        RANDOM.nextBytes(nonce);
        return nonce;
    }

    public static byte[] sha256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return md.digest(data);
    }
}
