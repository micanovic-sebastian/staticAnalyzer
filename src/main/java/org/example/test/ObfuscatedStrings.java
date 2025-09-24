package org.example.test;

import java.util.Base64;

public class ObfuscatedStrings {

    // This method should be flagged for using Base64 to hide a string.
    public String getHiddenCommand() {
        // "calc.exe" encoded in Base64
        String encodedCommand = "Y2FsYy5leGU=";
        byte[] decodedBytes = Base64.getDecoder().decode(encodedCommand);
        return new String(decodedBytes);
    }

    // This method should be flagged for using a loop with XOR to hide data.
    public String getXorDecryptedString() {
        byte[] encryptedData = { 22, 1, 3, 16, 28, 83, 22, 1, 3, 16 };
        byte key = 88; // The secret XOR key

        byte[] decryptedData = new byte[encryptedData.length];
        for (int i = 0; i < encryptedData.length; i++) {
            // The XOR operation is a strong indicator of simple encryption.
            decryptedData[i] = (byte) (encryptedData[i] ^ key);
        }
        return new String(decryptedData);
    }
}