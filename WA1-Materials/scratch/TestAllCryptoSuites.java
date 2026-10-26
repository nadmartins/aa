import common.CryptoConfig;
import common.CryptoService;
import java.util.HexFormat;
import java.util.Arrays;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.ChaCha20ParameterSpec;
import java.nio.ByteBuffer;
import java.security.MessageDigest;

public class TestAllCryptoSuites {
    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static void main(String[] args) {
        byte[] key128 = HexFormat.of().parseHex("000102030405060708090a0b0c0d0e0f");
        byte[] key256 = HexFormat.of().parseHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] macKey256 = HexFormat.of().parseHex("101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f");
        byte[] testData = "This is a real-time secure media streaming payload test block!".getBytes();

        CryptoConfig[] suites = new CryptoConfig[] {
            // 1. AES-256-GCM
            new CryptoConfig("AES", "GCM", "NULL", 96, "NULL", "NULL", key256, 256, null, 0),
            // 2. AES-128-GCM
            new CryptoConfig("AES", "GCM", "NULL", 96, "NULL", "NULL", key128, 128, null, 0),
            // 3. AES-256-CCM
            new CryptoConfig("AES", "CCM", "NULL", 96, "NULL", "NULL", key256, 256, null, 0),
            // 4. ChaCha20-Poly1305
            new CryptoConfig("ChaCha20", "Poly1305", "NULL", 96, "NULL", "NULL", key256, 256, null, 0),
            // 5. RC6-256-GCM
            new CryptoConfig("RC6", "GCM", "NULL", 96, "NULL", "NULL", key256, 256, null, 0),
            // 6. RC6-128-GCM
            new CryptoConfig("RC6", "GCM", "NULL", 96, "NULL", "NULL", key128, 128, null, 0),
            // 7. AES-256-CTR with HMAC-SHA256
            new CryptoConfig("AES", "CTR", "NULL", 128, "NoPadding", "HmacSHA256", key256, 256, macKey256, 256),
            // 8. AES-256-CBC with PKCS5Padding and HMAC-SHA256
            new CryptoConfig("AES", "CBC", "NULL", 128, "PKCS5Padding", "HmacSHA256", key256, 256, macKey256, 256),
            // 9. AES-256-ECB with PKCS5Padding and HMAC-SHA256
            new CryptoConfig("AES", "ECB", "NULL", 0, "PKCS5Padding", "HmacSHA256", key256, 256, macKey256, 256),
            // 10. RC6-256-CTR with HMAC-SHA256
            new CryptoConfig("RC6", "CTR", "NULL", 128, "NoPadding", "HmacSHA256", key256, 256, macKey256, 256),
            // 11. RC6-256-CBC with PKCS5Padding and HMAC-SHA256
            new CryptoConfig("RC6", "CBC", "NULL", 128, "PKCS5Padding", "HmacSHA256", key256, 256, macKey256, 256),
            // 12. RC6-256-ECB with PKCS5Padding and HMAC-SHA256
            new CryptoConfig("RC6", "ECB", "NULL", 0, "PKCS5Padding", "HmacSHA256", key256, 256, macKey256, 256),
            // 13. ChaCha20 stream cipher with HMAC-SHA256
            new CryptoConfig("ChaCha20", "NULL", "NULL", 96, "NULL", "HmacSHA256", key256, 256, macKey256, 256),
            // 14. AES-256-CTR with HMAC-SHA384
            new CryptoConfig("AES", "CTR", "NULL", 128, "NoPadding", "HmacSHA384", key256, 256, macKey256, 256),
            // 15. AES-256-CTR with HMAC-SHA512
            new CryptoConfig("AES", "CTR", "NULL", 128, "NoPadding", "HmacSHA512", key256, 256, macKey256, 256)
        };

        int passed = 0;
        for (CryptoConfig cfg : suites) {
            String desc = cfg.getAlgorithm() + "/" + cfg.getMode() + " (Key: " + cfg.getKeySize() + "b, MAC: " + cfg.getMacAlgorithm() + ")";
            try {
                byte[] ct = encryptMock(testData, cfg);
                byte[] pt = decryptMock(ct, cfg);
                if (Arrays.equals(testData, pt)) {
                    System.out.println("[PASS] " + desc + " -> ciphertext: " + ct.length + " bytes");
                    passed++;
                } else {
                    System.err.println("[FAIL - MISMATCH] " + desc);
                }
            } catch (Throwable t) {
                System.err.println("[ERROR] " + desc + " -> " + t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        }
        System.out.println("Result: " + passed + "/" + suites.length + " passed!");
    }

    private static byte[] encryptMock(byte[] plaintext, CryptoConfig config) throws Exception {
        boolean isAead = "GCM".equalsIgnoreCase(config.getMode()) 
            || "CCM".equalsIgnoreCase(config.getMode()) 
            || "Poly1305".equalsIgnoreCase(config.getMode())
            || "ChaCha20-Poly1305".equalsIgnoreCase(config.getAlgorithm());

        if (isAead) {
            byte[] nonce = CryptoService.generateNonce(12);
            String trans = config.getTransformation();
            if ("ChaCha20".equalsIgnoreCase(config.getAlgorithm()) && "Poly1305".equalsIgnoreCase(config.getMode())) {
                trans = "ChaCha20-Poly1305";
            }
            Cipher cipher = Cipher.getInstance(trans);
            if ("GCM".equalsIgnoreCase(config.getMode())) {
                cipher.init(Cipher.ENCRYPT_MODE, config.getSecretKey(), new GCMParameterSpec(128, nonce));
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, config.getSecretKey(), new IvParameterSpec(nonce));
            }
            byte[] ct = cipher.doFinal(plaintext);
            ByteBuffer bb = ByteBuffer.allocate(nonce.length + ct.length);
            bb.put(nonce);
            bb.put(ct);
            return bb.array();
        } else {
            boolean isEcb = "ECB".equalsIgnoreCase(config.getMode());
            boolean isChaCha = "ChaCha20".equalsIgnoreCase(config.getAlgorithm()) 
                && (config.getMode() == null || "NULL".equalsIgnoreCase(config.getMode()) || "None".equalsIgnoreCase(config.getMode()));
            boolean hasMac = config.getMacAlgorithm() != null && !config.getMacAlgorithm().equalsIgnoreCase("NULL");

            byte[] iv = null;
            Cipher cipher;
            if (isChaCha) {
                cipher = Cipher.getInstance("ChaCha20");
                iv = CryptoService.generateNonce(12);
                cipher.init(Cipher.ENCRYPT_MODE, config.getSecretKey(), new ChaCha20ParameterSpec(iv, 1));
            } else if (isEcb) {
                cipher = Cipher.getInstance(config.getAlgorithm() + "/ECB/" + (config.getPadding().equalsIgnoreCase("NULL") ? "NoPadding" : config.getPadding()));
                cipher.init(Cipher.ENCRYPT_MODE, config.getSecretKey());
            } else {
                cipher = Cipher.getInstance(config.getAlgorithm() + "/" + config.getMode() + "/" + (config.getPadding().equalsIgnoreCase("NULL") ? "NoPadding" : config.getPadding()));
                int ivSize = (config.getIvSize() > 0) ? (config.getIvSize() / 8) : 16;
                iv = CryptoService.generateNonce(ivSize);
                cipher.init(Cipher.ENCRYPT_MODE, config.getSecretKey(), new IvParameterSpec(iv));
            }

            byte[] ciphertext = cipher.doFinal(plaintext);

            if (hasMac) {
                Mac mac = Mac.getInstance(config.getMacAlgorithm());
                mac.init(config.getMacKey());
                if (iv != null) mac.update(iv);
                byte[] tag = mac.doFinal(ciphertext);

                int total = (iv != null ? iv.length : 0) + ciphertext.length + tag.length;
                ByteBuffer bb = ByteBuffer.allocate(total);
                if (iv != null) bb.put(iv);
                bb.put(ciphertext);
                bb.put(tag);
                return bb.array();
            } else {
                int total = (iv != null ? iv.length : 0) + ciphertext.length;
                ByteBuffer bb = ByteBuffer.allocate(total);
                if (iv != null) bb.put(iv);
                bb.put(ciphertext);
                return bb.array();
            }
        }
    }

    private static byte[] decryptMock(byte[] encryptedData, CryptoConfig config) throws Exception {
        boolean isAead = "GCM".equalsIgnoreCase(config.getMode()) 
            || "CCM".equalsIgnoreCase(config.getMode()) 
            || "Poly1305".equalsIgnoreCase(config.getMode())
            || "ChaCha20-Poly1305".equalsIgnoreCase(config.getAlgorithm());

        if (isAead) {
            if (encryptedData.length < 12) throw new IllegalArgumentException("Payload too short");
            byte[] nonce = Arrays.copyOfRange(encryptedData, 0, 12);
            byte[] ct = Arrays.copyOfRange(encryptedData, 12, encryptedData.length);
            String trans = config.getTransformation();
            if ("ChaCha20".equalsIgnoreCase(config.getAlgorithm()) && "Poly1305".equalsIgnoreCase(config.getMode())) {
                trans = "ChaCha20-Poly1305";
            }
            Cipher cipher = Cipher.getInstance(trans);
            if ("GCM".equalsIgnoreCase(config.getMode())) {
                cipher.init(Cipher.DECRYPT_MODE, config.getSecretKey(), new GCMParameterSpec(128, nonce));
            } else {
                cipher.init(Cipher.DECRYPT_MODE, config.getSecretKey(), new IvParameterSpec(nonce));
            }
            return cipher.doFinal(ct);
        } else {
            boolean isEcb = "ECB".equalsIgnoreCase(config.getMode());
            boolean isChaCha = "ChaCha20".equalsIgnoreCase(config.getAlgorithm()) 
                && (config.getMode() == null || "NULL".equalsIgnoreCase(config.getMode()) || "None".equalsIgnoreCase(config.getMode()));
            boolean hasMac = config.getMacAlgorithm() != null && !config.getMacAlgorithm().equalsIgnoreCase("NULL");

            int ivSize = isEcb ? 0 : (isChaCha ? 12 : ((config.getIvSize() > 0) ? (config.getIvSize() / 8) : 16));
            int macSize = 0;
            if (hasMac) {
                Mac m = Mac.getInstance(config.getMacAlgorithm());
                macSize = m.getMacLength();
            }

            if (encryptedData.length < ivSize + macSize) throw new IllegalArgumentException("Payload too short");
            byte[] iv = isEcb ? null : Arrays.copyOfRange(encryptedData, 0, ivSize);
            int ctEnd = encryptedData.length - macSize;
            byte[] ct = Arrays.copyOfRange(encryptedData, ivSize, ctEnd);

            if (hasMac) {
                byte[] receivedTag = Arrays.copyOfRange(encryptedData, ctEnd, encryptedData.length);
                Mac mac = Mac.getInstance(config.getMacAlgorithm());
                mac.init(config.getMacKey());
                if (iv != null) mac.update(iv);
                byte[] expectedTag = mac.doFinal(ct);
                if (!MessageDigest.isEqual(expectedTag, receivedTag)) {
                    throw new SecurityException("HMAC integrity check failed!");
                }
            }

            Cipher cipher;
            if (isChaCha) {
                cipher = Cipher.getInstance("ChaCha20");
                cipher.init(Cipher.DECRYPT_MODE, config.getSecretKey(), new ChaCha20ParameterSpec(iv, 1));
            } else if (isEcb) {
                cipher = Cipher.getInstance(config.getAlgorithm() + "/ECB/" + (config.getPadding().equalsIgnoreCase("NULL") ? "NoPadding" : config.getPadding()));
                cipher.init(Cipher.DECRYPT_MODE, config.getSecretKey());
            } else {
                cipher = Cipher.getInstance(config.getAlgorithm() + "/" + config.getMode() + "/" + (config.getPadding().equalsIgnoreCase("NULL") ? "NoPadding" : config.getPadding()));
                cipher.init(Cipher.DECRYPT_MODE, config.getSecretKey(), new IvParameterSpec(iv));
            }
            return cipher.doFinal(ct);
        }
    }
}
