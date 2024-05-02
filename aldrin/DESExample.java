import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class DESExample {

    public static void main(String[] args) throws Exception {
        // Generate DES key
        SecretKey secretKey = generateDESKey();

        // Create Cipher instance
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

        // Plain text
        String plainText = "Hello, aldrin joe cagubcub!";
        System.out.println("Original: " + plainText);

        // Convert String to byte array
        byte[] plainTextBytes = plainText.getBytes(StandardCharsets.UTF_8);

        // Encryption
        byte[] encryptedBytes = performEncryption(cipher, secretKey, plainTextBytes);
        String encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
        System.out.println("Encrypted: " + encryptedText);

        // Decryption
        byte[] decryptedBytes = performDecryption(cipher, secretKey, encryptedBytes);
        String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);
        System.out.println("Decrypted: " + decryptedText);
    }

    private static SecretKey generateDESKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        return keyGenerator.generateKey();
    }

    private static byte[] performEncryption(Cipher cipher, SecretKey secretKey, byte[] plainTextBytes) throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(plainTextBytes);
    }

    private static byte[] performDecryption(Cipher cipher, SecretKey secretKey, byte[] encryptedBytes) throws Exception {
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(encryptedBytes);
    }
}
