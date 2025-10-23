package org.example.analyzer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

/**
 * Diese Klasse kümmert sich um die gesamte Kommunikation mit der VirusTotal API
 * Sie kann Datei-Hashes prüfen, Dateien hochladen und Analyse-Berichte abrufen
 */
public class VirusTotalAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(VirusTotalAnalyzer.class);
    private static final String VT_API_URL = "https://www.virustotal.com/api/v3/";
    private static final long POLLING_INTERVAL_MS = 20000; // 20 Sekunden
    private static final int MAX_POLLS = 15; // Maximal 5 Minuten (15 Polls * 20s)

    private final String apiKey;
    private final OkHttpClient client;
    private final ObjectMapper mapper;

    public VirusTotalAnalyzer() {

        // Setzt den API-Schlüssel
        this.apiKey = "c830faa612499becfca3247c5688cf38f4d4b6b98d518285abfee871a1432e92";

        // Konfiguriert den HTTP-Client für Timeouts
        this.client = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(60, TimeUnit.SECONDS) // Länger für Uploads
                .readTimeout(30, TimeUnit.SECONDS)
                .build();
        this.mapper = new ObjectMapper();
    }

    /**
     * Prüft ob ein API-Schlüssel vorhanden ist
     * @return true wenn der Schlüssel konfiguriert ist
     */
    public boolean isConfigured() {
        return this.apiKey != null && !this.apiKey.isEmpty();
    }

    /**
     * Berechnet den SHA-256 Hash einer Datei
     * @param filePath Der Pfad zur Datei
     * @return Der SHA-256 Hash als Hex-String
     */
    private String getFileSha256(String filePath) throws IOException {
        try (FileInputStream fis = new FileInputStream(filePath)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[8192];
            int bytesRead;
            // Datei blockweise einlesen und den Hash aktualisieren
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
            byte[] hash = digest.digest();
            // Hash-Bytes in einen Hex-String umwandeln
            StringBuilder hexString = new StringBuilder(2 * hash.length);
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Could not find SHA-256 algorithm", e);
        }
    }

    /**
     * Prüft den SHA-256 Hash einer Datei bei VirusTotal
     * @param filePath Pfad zur Datei
     * @return true wenn die Datei als bösartig oder verdächtig bekannt ist
     */
    public boolean checkFileHash(String filePath) throws IOException {
        String sha256Hash = getFileSha256(filePath);
        LOGGER.info("Calculated SHA-256 hash: {}", sha256Hash);
        String reportUrl = VT_API_URL + "files/" + sha256Hash;

        // HTTP-Anfrage mit API-Schlüssel im Header erstellen
        Request request = new Request.Builder()
                .url(reportUrl)
                .get()
                .header("x-apikey", this.apiKey)
                .header("accept", "application/json")
                .build();

        LOGGER.info("Querying VirusTotal for known hash report...");

        try (Response response = client.newCall(request).execute()) {

            String responseBody = response.body().string();

            // 404 bedeutet dass der Hash bei VT unbekannt ist
            if (response.code() == 404) {
                LOGGER.info("VirusTotal Hash Check: UNKNOWN (File hash not found). Proceeding.");
                return false;
            }

            if (!response.isSuccessful()) {
                LOGGER.error("VirusTotal Hash Report (Error Response): {}", responseBody);
                throw new IOException("Failed to retrieve VirusTotal hash report: " + response.code());
            }

            // Erfolgreiche Antwort parsen
            LOGGER.info("VirusTotal Hash Report (Success Response): {}", responseBody);
            JsonNode root = mapper.readTree(responseBody);

            JsonNode stats = root.path("data").path("attributes").path("last_analysis_stats");
            int maliciousCount = stats.path("malicious").asInt();
            int suspiciousCount = stats.path("suspicious").asInt();

            // Prüfen ob der Hash als bösartig oder verdächtig eingestuft wurde
            if (maliciousCount > 0 || suspiciousCount > 0) {
                LOGGER.warn("[CRITICAL] VirusTotal Hash Scan Result: MALICIOUS ({}) / SUSPICIOUS ({})", maliciousCount, suspiciousCount);
                return true;
            } else {
                LOGGER.info("VirusTotal Hash Scan Result: CLEAN");
                return false;
            }
        }
    }

    /**
     * Lädt eine Datei zur Analyse zu VirusTotal hoch
     * @param filePath Pfad zur Datei die hochgeladen werden soll
     * @return Die Analyse-ID von VirusTotal
     */
    public String uploadFile(String filePath) throws IOException {
        File file = new File(filePath);
        if (!file.exists()) {
            throw new IOException("File not found: " + filePath);
        }

        // Multipart-Body für den Datei-Upload erstellen
        RequestBody requestBody = new MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart("file", file.getName(),
                        RequestBody.create(file, MediaType.parse("application/octet-stream")))
                .build();

        Request request = new Request.Builder()
                .url(VT_API_URL + "files")
                .header("x-apikey", this.apiKey)
                .header("accept", "application/json")
                .post(requestBody)
                .build();

        LOGGER.info("Uploading {} to VirusTotal for analysis...", file.getName());

        try (Response response = client.newCall(request).execute()) {
            String responseBody = response.body().string();

            if (!response.isSuccessful()) {
                LOGGER.error("VirusTotal Upload Response (Error): {}", responseBody);
                throw new IOException("VirusTotal upload failed: " + response.code());
            }

            // Antwort parsen um die Analyse-ID zu erhalten
            LOGGER.info("VirusTotal Upload Response (Success): {}", responseBody);
            JsonNode root = mapper.readTree(responseBody);

            String analysisId = root.path("data").path("id").asText();
            LOGGER.info("Upload successful. Analysis ID: {}", analysisId);
            return analysisId;
        }
    }

    /**
     * Ruft den Analyse-Bericht für eine Analyse-ID ab
     * Pollt die API bis die Analyse abgeschlossen ist oder ein Timeout auftritt
     * @param analysisId Die ID die vom Upload zurückgegeben wurde
     * @return true wenn die Analyse bösartig oder verdächtig ist
     */
    public boolean getAnalysisReport(String analysisId) throws IOException, InterruptedException {
        String analysisUrl = VT_API_URL + "analyses/" + analysisId;

        // Polling-Schleife
        for (int i = 0; i < MAX_POLLS; i++) {
            Request request = new Request.Builder()
                    .url(analysisUrl)
                    .header("x-apikey", this.apiKey)
                    .header("accept", "application/json")
                    .get()
                    .build();

            try (Response response = client.newCall(request).execute()) {
                String responseBody = response.body().string();

                if (!response.isSuccessful()) {
                    // 404 kann bedeuten dass der Bericht noch nicht existiert
                    if (response.code() == 404) {
                        LOGGER.warn("VirusTotal analysis report not found yet. Retrying in {}s...", POLLING_INTERVAL_MS / 1000);
                        Thread.sleep(POLLING_INTERVAL_MS);
                        continue;
                    }
                    LOGGER.error("VirusTotal Report Response (Error): {}", responseBody);
                    throw new IOException("VirusTotal report retrieval failed: " + response.code());
                }

                LOGGER.info("VirusTotal Analysis Poll Response (Success): {}", responseBody);
                JsonNode root = mapper.readTree(responseBody);

                // Den Status der Analyse prüfen
                String status = root.path("data").path("attributes").path("status").asText();

                if ("completed".equals(status)) {
                    // Analyse ist abgeschlossen
                    LOGGER.info("VirusTotal analysis complete.");
                    JsonNode stats = root.path("data").path("attributes").path("stats");
                    int maliciousCount = stats.path("malicious").asInt();
                    int suspiciousCount = stats.path("suspicious").asInt();

                    if (maliciousCount > 0 || suspiciousCount > 0) {
                        LOGGER.warn("[CRITICAL] VirusTotal Scan Result: MALICIOUS ({}) / SUSPICIOUS ({})", maliciousCount, suspiciousCount);
                        return true;
                    } else {
                        LOGGER.info("VirusTotal Scan Result: CLEAN");
                        return false;
                    }
                } else {
                    // Analyse läuft noch
                    LOGGER.info("VirusTotal analysis status: '{}'. Waiting {}s...", status, POLLING_INTERVAL_MS / 1000);
                    Thread.sleep(POLLING_INTERVAL_MS);
                }
            }
        }
        // Timeout wenn die maximale Anzahl an Polls erreicht wird
        throw new IOException("VirusTotal analysis timed out after " + (MAX_POLLS * POLLING_INTERVAL_MS / 1000) + " seconds.");
    }
}
