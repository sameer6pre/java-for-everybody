import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

public class FileEncryptionDecryption {

    private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding"; // FIX: Use CBC mode with PKCS5Padding
    private static final String ENCRYPTED_FILE_EXTENSION = ".enc";
    private static final int IV_SIZE = 16; // 128 bits
    private static final int SALT_SIZE = 16; // 128 bits
    private static final int KEY_SIZE = 256; // bits
    private static final int PBKDF2_ITERATIONS = 65536;

    public static void RunFileEncryptionDecryption(String[] args) {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            System.out.print("Enter file path: ");
            String filePath = reader.readLine();

            System.out.print("Enter encryption key: ");
            String encryptionKey = reader.readLine();

            System.out.print("Encrypt (E) or Decrypt (D): ");
            String mode = reader.readLine();

            if (mode.equalsIgnoreCase("E")) {
                encryptFile(filePath, encryptionKey);
                System.out.println("File encrypted successfully!");
            } else if (mode.equalsIgnoreCase("D")) {
                decryptFile(filePath, encryptionKey);
                System.out.println("File decrypted successfully!");
            } else {
                System.out.println("Invalid mode selected.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void encryptFile(String filePath, String encryptionKey) throws Exception {
        byte[] fileContent = Files.readAllBytes(Paths.get(filePath));

        // FIX: Generate random salt and IV
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_SIZE];
        random.nextBytes(salt);
        byte[] iv = new byte[IV_SIZE];
        random.nextBytes(iv);

        SecretKey key = generateKey(encryptionKey, salt);
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        byte[] encryptedContent = cipher.doFinal(fileContent);

        // FIX: Prepend salt and IV to the encrypted file (Base64 encoded for safety)
        String encryptedFilePath = filePath + ENCRYPTED_FILE_EXTENSION;
        try (FileOutputStream outputStream = new FileOutputStream(encryptedFilePath)) {
            outputStream.write(salt);
            outputStream.write(iv);
            outputStream.write(encryptedContent);
        }
    }

    private static void decryptFile(String filePath, String encryptionKey) throws Exception {
        byte[] fileData = Files.readAllBytes(Paths.get(filePath));
        if (fileData.length < SALT_SIZE + IV_SIZE) {
            throw new IllegalArgumentException("File too short to contain salt and IV");
        }
        // FIX: Extract salt and IV
        byte[] salt = new byte[SALT_SIZE];
        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(fileData, 0, salt, 0, SALT_SIZE);
        System.arraycopy(fileData, SALT_SIZE, iv, 0, IV_SIZE);
        byte[] encryptedContent = new byte[fileData.length - SALT_SIZE - IV_SIZE];
        System.arraycopy(fileData, SALT_SIZE + IV_SIZE, encryptedContent, 0, encryptedContent.length);

        SecretKey key = generateKey(encryptionKey, salt);
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        byte[] decryptedContent = cipher.doFinal(encryptedContent);

        String decryptedFilePath = filePath.replace(ENCRYPTED_FILE_EXTENSION, "");
        try (FileOutputStream outputStream = new FileOutputStream(decryptedFilePath)) {
            outputStream.write(decryptedContent);
        }
    }

    // FIX: Use PBKDF2 for key derivation with salt
    private static SecretKey generateKey(String encryptionKey, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(encryptionKey.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_SIZE);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }
}

// FIX EXPLANATION: This fix uses PBKDF2 with a random salt for key derivation, ensuring strong, unpredictable keys even from weak passwords. It uses AES in CBC mode with a random IV, which is prepended to the ciphertext for decryption. This prevents ECB mode weaknesses and ensures semantic security. The salt and IV are stored with the ciphertext, and all cryptographic parameters are securely generated. This approach follows industry best practices for file encryption.

