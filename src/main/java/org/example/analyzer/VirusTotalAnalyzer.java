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

public class VirusTotalAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(VirusTotalAnalyzer.class);
    private static final String VT_API_URL = "https://www.virustotal.com/api/v3/";
    private static final long POLLING_INTERVAL_MS = 20000; // 20 seconds
    private static final int MAX_POLLS = 15; // Max 5 minutes (15 polls * 20s)

    private final String apiKey;
    private final OkHttpClient client;
    private final ObjectMapper mapper;

    public VirusTotalAnalyzer() {
        // NOTE: The API key should ideally be read from an environment variable
        // for better security practices, e.g., System.getenv("VT_API_KEY");
        this.apiKey = "c830faa612499becfca3247c5688cf38f4d4b6b98d518285abfee871a1432e92";

        this.client = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(60, TimeUnit.SECONDS) // Longer for uploads
                .readTimeout(30, TimeUnit.SECONDS)
                .build();
        this.mapper = new ObjectMapper();
    }

    public boolean isConfigured() {
        return this.apiKey != null && !this.apiKey.isEmpty();
    }

    private String getFileSha256(String filePath) throws IOException {
        try (FileInputStream fis = new FileInputStream(filePath)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
            byte[] hash = digest.digest();
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

    public boolean checkFileHash(String filePath) throws IOException {
        String sha256Hash = getFileSha256(filePath);
        LOGGER.info("Calculated SHA-256 hash: {}", sha256Hash);
        String reportUrl = VT_API_URL + "files/" + sha256Hash;

        Request request = new Request.Builder()
                .url(reportUrl)
                .get()
                .header("x-apikey", this.apiKey)
                .header("accept", "application/json")
                .build();

        LOGGER.info("Querying VirusTotal for known hash report...");

        try (Response response = client.newCall(request).execute()) {
            // --- MODIFICATION: ADDED LOGGING ---
            // Read the response body into a string variable *first* so it can be logged.
            // The response body can only be read once.
            String responseBody = response.body().string();

            if (response.code() == 404) {
                LOGGER.info("VirusTotal Hash Check: UNKNOWN (File hash not found). Proceeding.");
                return false;
            }

            if (!response.isSuccessful()) {
                // Log the full error response from the API.
                LOGGER.error("VirusTotal Hash Report (Error Response): {}", responseBody);
                throw new IOException("Failed to retrieve VirusTotal hash report: " + response.code());
            }

            // Log the full successful response for debugging and transparency.
            LOGGER.info("VirusTotal Hash Report (Success Response): {}", responseBody);
            JsonNode root = mapper.readTree(responseBody);
            // --- END OF MODIFICATION ---

            JsonNode stats = root.path("data").path("attributes").path("last_analysis_stats");
            int maliciousCount = stats.path("malicious").asInt();
            int suspiciousCount = stats.path("suspicious").asInt();

            if (maliciousCount > 0 || suspiciousCount > 0) {
                LOGGER.warn("[CRITICAL] VirusTotal Hash Scan Result: MALICIOUS ({}) / SUSPICIOUS ({})", maliciousCount, suspiciousCount);
                return true;
            } else {
                LOGGER.info("VirusTotal Hash Scan Result: CLEAN");
                return false;
            }
        }
    }

    public String uploadFile(String filePath) throws IOException {
        File file = new File(filePath);
        if (!file.exists()) {
            throw new IOException("File not found: " + filePath);
        }

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
            // --- MODIFICATION: ADDED LOGGING ---
            String responseBody = response.body().string();

            if (!response.isSuccessful()) {
                LOGGER.error("VirusTotal Upload Response (Error): {}", responseBody);
                throw new IOException("VirusTotal upload failed: " + response.code());
            }

            LOGGER.info("VirusTotal Upload Response (Success): {}", responseBody);
            JsonNode root = mapper.readTree(responseBody);
            // --- END OF MODIFICATION ---

            String analysisId = root.path("data").path("id").asText();
            LOGGER.info("Upload successful. Analysis ID: {}", analysisId);
            return analysisId;
        }
    }

    public boolean getAnalysisReport(String analysisId) throws IOException, InterruptedException {
        String analysisUrl = VT_API_URL + "analyses/" + analysisId;

        for (int i = 0; i < MAX_POLLS; i++) {
            Request request = new Request.Builder()
                    .url(analysisUrl)
                    .header("x-apikey", this.apiKey)
                    .header("accept", "application/json")
                    .get()
                    .build();

            try (Response response = client.newCall(request).execute()) {
                // --- MODIFICATION: ADDED LOGGING ---
                String responseBody = response.body().string();

                if (!response.isSuccessful()) {
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
                // --- END OF MODIFICATION ---

                String status = root.path("data").path("attributes").path("status").asText();

                if ("completed".equals(status)) {
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
                    LOGGER.info("VirusTotal analysis status: '{}'. Waiting {}s...", status, POLLING_INTERVAL_MS / 1000);
                    Thread.sleep(POLLING_INTERVAL_MS);
                }
            }
        }
        throw new IOException("VirusTotal analysis timed out after " + (MAX_POLLS * POLLING_INTERVAL_MS / 1000) + " seconds.");
    }
}

