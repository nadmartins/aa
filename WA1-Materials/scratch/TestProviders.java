import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;

public class TestProviders {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        
        try {
            Cipher cipher = Cipher.getInstance("RC6/GCM/NoPadding");
            System.out.println("Got cipher: " + cipher.getProvider().getName());
            
            byte[] key = new byte[32]; // 256 bits
            byte[] nonce = new byte[12];
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "RC6"), new GCMParameterSpec(128, nonce));
            byte[] ct = cipher.doFinal("Hello World".getBytes());
            System.out.println("Encryption succeeded! ct length: " + ct.length);
            
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "RC6"), new GCMParameterSpec(128, nonce));
            byte[] pt = cipher.doFinal(ct);
            System.out.println("Decryption succeeded: " + new String(pt));
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }
}
