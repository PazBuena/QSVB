import java.nio.file.*;
import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class MM {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int KEY_SIZE = 256;
    private static final int IV_SIZE = 16;
    private static final int SALT_SIZE = 16;
    private static final int ITERATIONS = 20859300;

    public static void main(String[] args) throws Exception {
        String password = "";
        Path inputPath = Paths.get("");
        Path outputPath = Paths.get("");

        byte[] encryptedFile = Files.readAllBytes(inputPath);

        byte[] salt = new byte[SALT_SIZE];
        byte[] iv = new byte[IV_SIZE];
        byte[] encryptedData = new byte[encryptedFile.length - SALT_SIZE - IV_SIZE];

        System.arraycopy(encryptedFile, 0, salt, 0, SALT_SIZE);
        System.arraycopy(encryptedFile, SALT_SIZE, iv, 0, IV_SIZE);
        System.arraycopy(encryptedFile, SALT_SIZE + IV_SIZE, encryptedData, 0, encryptedData.length);

        SecretKey key = generateKeyFromPassword(password, salt);
        byte[] decryptedData = decrypt(encryptedData, key, iv);

        Files.write(outputPath, decryptedData);
    }

    private static SecretKey generateKeyFromPassword(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_SIZE);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    private static byte[] decrypt(byte[] encryptedData, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(encryptedData);
    }
    
}
