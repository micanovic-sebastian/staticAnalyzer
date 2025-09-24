package org.example.test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class PayloadEncryptor {

    // This method should be flagged for using strong encryption APIs.
    public String encryptData() {
        try {
            String dataToHide = "Stolen user credentials and secrets";

            // Generate a secret key, just like ransomware would.
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey secretKey = keyGen.generateKey();

            // Initialize the cipher to encrypt.
            Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] encryptedData = aesCipher.doFinal(dataToHide.getBytes());

            // Return the encrypted data, often to be sent over the network.
            return Base64.getEncoder().encodeToString(encryptedData);

        } catch (Exception e) {
            return null;
        }
    }
}