package common;

import java.io.File;
import java.util.Base64;
import java.util.HexFormat;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class CryptoConfig {

    private final String algorithm;
    private final String mode;
    private final String ivValue;
    private final int ivSize;
    private final String padding;
    private final String macAlgorithm;
    private final byte[] secretKeyBytes;
    private final int keySize;
    private final byte[] macKeyBytes;
    private final int macKeySize;

    public CryptoConfig(String algorithm, String mode, String ivValue, int ivSize, String padding,
                        String macAlgorithm, byte[] secretKeyBytes, int keySize,
                        byte[] macKeyBytes, int macKeySize) {
        this.algorithm = algorithm != null ? algorithm.trim() : "AES";
        this.mode = mode != null ? mode.trim() : "GCM";
        this.ivValue = ivValue != null ? ivValue.trim() : "NULL";
        this.ivSize = ivSize;
        this.padding = padding != null ? padding.trim() : "NULL";
        this.macAlgorithm = normalizeMacAlgorithm(macAlgorithm);
        this.secretKeyBytes = secretKeyBytes;
        this.keySize = keySize;
        this.macKeyBytes = macKeyBytes;
        this.macKeySize = macKeySize;
    }

    public static CryptoConfig load(String filePath) throws Exception {
        File file = findConfigFile(filePath);
        if (file == null || !file.exists()) {
            throw new IllegalArgumentException("Config File not found: " + filePath);
        }

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(file);
        doc.getDocumentElement().normalize();

        String algorithm = getTagValue(doc, "Algorithm");
        String mode = getTagValue(doc, "Mode");
        String ivValue = getTagValue(doc, "IV");
        String ivSizeStr = getTagValue(doc, "IVSize", "IVSIZE", "IvSize", "ivsize");
        int ivSize = (ivSizeStr != null && !ivSizeStr.equalsIgnoreCase("NULL")) ? Integer.parseInt(ivSizeStr) : 0;
        String padding = getTagValue(doc, "Padding", "padding");

        String macAlgorithm = "NULL";
        NodeList macSuites = doc.getElementsByTagName("MACSuite");
        if (macSuites.getLength() == 0) {
            macSuites = doc.getElementsByTagName("MACsuite");
        }
        if (macSuites.getLength() == 0) {
            macSuites = doc.getElementsByTagName("MacSuite");
        }
        if (macSuites.getLength() > 0) {
            Element macEl = (Element) macSuites.item(0);
            NodeList algList = macEl.getElementsByTagName("Algorithm");
            if (algList.getLength() > 0) {
                macAlgorithm = algList.item(0).getTextContent().trim();
            }
        }

        String sKeyStr = getTagValue(doc, "SKey", "skey", "Skey");
        String keySizeStr = getTagValue(doc, "KeySize", "Keysize", "keysize", "KEYSIZE");
        int keySize = (keySizeStr != null && !keySizeStr.equalsIgnoreCase("NULL")) ? Integer.parseInt(keySizeStr) : 0;
        byte[] secretKeyBytes = parseKeyOrData(sKeyStr);

        String macKeyStr = getTagValue(doc, "MacKey", "mackey", "MACKEY", "MacKeye");
        String macKeySizeStr = getTagValue(doc, "MacKeySize", "Mackeysize", "mackeysize", "MACKEYSIZE");
        int macKeySize = (macKeySizeStr != null && !macKeySizeStr.equalsIgnoreCase("NULL")) ? Integer.parseInt(macKeySizeStr) : 0;
        byte[] macKeyBytes = parseKeyOrData(macKeyStr);

        return new CryptoConfig(algorithm, mode, ivValue, ivSize, padding,
                macAlgorithm, secretKeyBytes, keySize, macKeyBytes, macKeySize);
    }

    private static File findConfigFile(String path) {
        File f = new File(path);
        if (f.exists()) return f;

        String[] fallbacks = new String[] {
            "WA1-Materials/streamserver/" + path,
            "WA1-Materials/streamproxy/" + path,
            "streamserver/" + path,
            "streamproxy/" + path,
            "configs/" + path,
            "WA1-Materials/configs/" + path,
            "../streamserver/" + path,
            "../streamproxy/" + path
        };

        for (String fb : fallbacks) {
            File alt = new File(fb);
            if (alt.exists()) return alt;
        }
        return f;
    }

    private static String getTagValue(Document doc, String... tagNames) {
        for (String tagName : tagNames) {
            NodeList list = doc.getElementsByTagName(tagName);
            if (list.getLength() > 0 && list.item(0).getTextContent() != null) {
                String val = list.item(0).getTextContent().trim();
                if (!val.isEmpty()) return val;
            }
        }
        // Fallback: search case-insensitively across all elements
        NodeList all = doc.getElementsByTagName("*");
        for (int i = 0; i < all.getLength(); i++) {
            Element el = (Element) all.item(i);
            for (String tagName : tagNames) {
                if (el.getTagName().equalsIgnoreCase(tagName)) {
                    String val = el.getTextContent();
                    if (val != null && !val.trim().isEmpty()) {
                        return val.trim();
                    }
                }
            }
        }
        return "NULL";
    }

    public static byte[] parseKeyOrData(String raw) {
        if (raw == null || raw.equalsIgnoreCase("NULL") || raw.isBlank()) {
            return null;
        }
        String clean = raw.replaceAll("\\s+", "");
        // Check if hex: even length and only hex digits
        if (clean.matches("^[0-9a-fA-F]+$")) {
            try {
                return HexFormat.of().parseHex(clean);
            } catch (Exception ignored) {}
        }
        // Try Base64
        try {
            return Base64.getDecoder().decode(clean);
        } catch (Exception e) {
            throw new IllegalArgumentException("Key material is neither valid Hex nor Base64: " + raw);
        }
    }

    public static String normalizeMacAlgorithm(String mac) {
        if (mac == null || mac.equalsIgnoreCase("NULL") || mac.isBlank()) {
            return "NULL";
        }
        String clean = mac.trim();
        String upper = clean.toUpperCase().replace("-", "");
        if (upper.equals("HMACSHA256") || upper.equals("HMAC256")) return "HmacSHA256";
        if (upper.equals("HMACSHA384") || upper.equals("HMAC384")) return "HmacSHA384";
        if (upper.equals("HMACSHA512") || upper.equals("HMAC512")) return "HmacSHA512";
        if (upper.equals("HMACMD5")) return "HmacMD5";
        return clean;
    }

    public String toPcc() {
        return algorithm + "/" + mode + "/" + ivValue + "/" + padding;
    }

    public boolean isPccCompatible(String pcc) {
        if (pcc == null) return false;
        String[] parts = pcc.split("/");
        if (parts.length < 4) return false;
        String pccAlg = parts[0];
        String pccMode = parts[1];
        String pccPad = parts[3];

        if (!this.algorithm.equalsIgnoreCase(pccAlg)) return false;
        if (!this.mode.equalsIgnoreCase(pccMode)) return false;

        if (isAead()) {
            return true;
        }
        return this.padding.equalsIgnoreCase(pccPad);
    }

    public String getTransformation() {
        String pad = (padding == null || padding.equalsIgnoreCase("NULL")) ? "NoPadding" : padding;
        if (algorithm.equalsIgnoreCase("ChaCha20") && (mode.equalsIgnoreCase("Poly1305") || "Poly1305".equalsIgnoreCase(mode))) {
            return "ChaCha20-Poly1305";
        }
        if (algorithm.equalsIgnoreCase("ChaCha20") && (mode == null || mode.equalsIgnoreCase("NULL") || mode.equalsIgnoreCase("None"))) {
            return "ChaCha20";
        }
        if (isAead()) {
            return algorithm + "/" + mode + "/NoPadding";
        }
        return algorithm + "/" + mode + "/" + pad;
    }

    public boolean isAead() {
        return "GCM".equalsIgnoreCase(mode) 
            || "CCM".equalsIgnoreCase(mode) 
            || "Poly1305".equalsIgnoreCase(mode) 
            || "ChaCha20-Poly1305".equalsIgnoreCase(algorithm)
            || (algorithm != null && algorithm.toLowerCase().contains("poly1305"));
    }

    public SecretKey getSecretKey() {
        if (secretKeyBytes == null) return null;
        String keyAlg = algorithm;
        if (algorithm.equalsIgnoreCase("ChaCha20-Poly1305")) {
            keyAlg = "ChaCha20";
        }
        return new SecretKeySpec(secretKeyBytes, keyAlg);
    }

    public SecretKey getMacKey() {
        if (macKeyBytes == null) return null;
        return new SecretKeySpec(macKeyBytes, macAlgorithm);
    }

    public boolean isCompatibleWith(CryptoConfig other) {
        if (other == null) return false;
        return this.algorithm.equalsIgnoreCase(other.getAlgorithm())
                && this.mode.equalsIgnoreCase(other.getMode())
                && (this.keySize == 0 || other.getKeySize() == 0 || this.keySize == other.getKeySize())
                && (this.padding.equalsIgnoreCase(other.getPadding()) || (isAead() && other.isAead()))
                && this.macAlgorithm.equalsIgnoreCase(other.getMacAlgorithm());
    }

    // Getters
    public String getAlgorithm() { return algorithm; }
    public String getMode() { return mode; }
    public String getIvValue() { return ivValue; }
    public int getIvSize() { return ivSize; }
    public String getPadding() { return padding; }
    public String getMacAlgorithm() { return macAlgorithm; }
    public int getKeySize() { return keySize; }
    public byte[] getSecretKeyBytes() { return secretKeyBytes; }
    public byte[] getMacKeyBytes() { return macKeyBytes; }
    public int getMacKeySize() { return macKeySize; }
}
