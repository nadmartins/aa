import common.CryptoConfig;
import common.CryptoService;
import java.util.HexFormat;

public class TestCipherSuites {
    public static void main(String[] args) {
        // Test various cipher configurations
        byte[] key128 = HexFormat.of().parseHex("000102030405060708090a0b0c0d0e0f");
        byte[] key256 = HexFormat.of().parseHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] macKey256 = HexFormat.of().parseHex("101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f");
        byte[] data = "Hello Secure Streaming World! Testing payload encryption.".getBytes();

        CryptoConfig[] configs = new CryptoConfig[] {
            // 1. AES/GCM
            new CryptoConfig("AES", "GCM", "NULL", 96, "NULL", "NULL", key256, 256, null, 0),
            // 2. RC6/GCM
            new CryptoConfig("RC6", "GCM", "NULL", 96, "NULL", "NULL", key256, 256, null, 0),
            // 3. ChaCha20/Poly1305
            new CryptoConfig("ChaCha20", "Poly1305", "NULL", 96, "NULL", "NULL", key256, 256, null, 0),
            // 4. AES/CTR with HMAC-SHA256
            new CryptoConfig("AES", "CTR", "NULL", 128, "NoPadding", "HmacSHA256", key256, 256, macKey256, 256),
            // 5. AES/CBC with PKCS5Padding and HMAC-SHA256
            new CryptoConfig("AES", "CBC", "NULL", 128, "PKCS5Padding", "HmacSHA256", key256, 256, macKey256, 256),
            // 6. RC6/CTR with HMAC-SHA256
            new CryptoConfig("RC6", "CTR", "NULL", 128, "NoPadding", "HmacSHA256", key256, 256, macKey256, 256),
            // 7. RC6/CBC with PKCS5Padding and HMAC-SHA256
            new CryptoConfig("RC6", "CBC", "NULL", 128, "PKCS5Padding", "HmacSHA256", key256, 256, macKey256, 256),
            // 8. AES/ECB with PKCS5Padding and HMAC-SHA256
            new CryptoConfig("AES", "ECB", "NULL", 0, "PKCS5Padding", "HmacSHA256", key256, 256, macKey256, 256),
            // 9. AES/CCM
            new CryptoConfig("AES", "CCM", "NULL", 96, "NULL", "NULL", key256, 256, null, 0),
            // 10. ChaCha20 (standalone stream cipher) with HMAC-SHA256
            new CryptoConfig("ChaCha20", "NULL", "NULL", 96, "NULL", "HmacSHA256", key256, 256, macKey256, 256),
        };

        for (CryptoConfig cfg : configs) {
            String name = cfg.getAlgorithm() + "/" + cfg.getMode() + " (MAC: " + cfg.getMacAlgorithm() + ")";
            try {
                byte[] enc = CryptoService.encrypt(data, cfg);
                byte[] dec = CryptoService.decrypt(enc, cfg);
                if (java.util.Arrays.equals(data, dec)) {
                    System.out.println("SUCCESS: " + name + " -> ct size: " + enc.length);
                } else {
                    System.out.println("FAILED (data mismatch): " + name);
                }
            } catch (Throwable t) {
                System.out.println("ERROR: " + name + " -> " + t.getClass().getSimpleName() + ": " + t.getMessage());
            }
        }
    }
}
