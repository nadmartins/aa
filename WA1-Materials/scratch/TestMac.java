import javax.crypto.Mac;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class TestMac {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        String[] algs = {
            "HmacSHA256", "HMAC-SHA256", "HMACSHA256",
            "HmacSHA384", "HMAC-SHA384", "HMACSHA384",
            "HmacSHA512", "HMAC-SHA-512", "HMACSHA512"
        };
        for (String a : algs) {
            try {
                Mac mac = Mac.getInstance(a);
                System.out.println("VALID: " + a + " -> " + mac.getAlgorithm());
            } catch (Exception e) {
                System.out.println("INVALID: " + a);
            }
        }
    }
}
