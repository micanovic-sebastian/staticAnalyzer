package org.example.analyzer;


import java.net.Socket;

public class HardcodedSecrets {

    // This method should be flagged for containing a hardcoded IP address.
    public void connectToC2Server() {
        String serverIp = "127.0.0.1"; // A suspicious hardcoded IP.
        int port = 4444;                 // A common malware port.
        try {
            new Socket(serverIp, port);
        } catch (Exception e) {
            // Ignored.
        }
    }

    // This method should NOT be flagged, as the port is common and the IP is a localhost DNS name.
    public void connectToLocalhost() {
        String serverIp = "localhost";
        int port = 8080; // A common development port.
        try {
            new Socket(serverIp, port);
        } catch (Exception e) {
            // Ignored.
        }
    }
}