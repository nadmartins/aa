import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.ChaCha20ParameterSpec;

public class TestChaCha {
    public static void main(String[] args) throws Exception {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        Cipher cipher = Cipher.getInstance("ChaCha20");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new ChaCha20ParameterSpec(nonce, 1));
        byte[] ct = cipher.doFinal("Hello ChaCha20".getBytes());
        System.out.println("ChaCha20 standalone encrypted: " + ct.length);
        
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new ChaCha20ParameterSpec(nonce, 1));
        byte[] pt = cipher.doFinal(ct);
        System.out.println("ChaCha20 decrypted: " + new String(pt));
    }
}
