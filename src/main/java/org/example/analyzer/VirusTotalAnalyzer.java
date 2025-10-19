package org.example.analyzer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.concurrent.TimeUnit;

public class VirusTotalAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(VirusTotalAnalyzer.class);
    private static final String VT_API_URL = "https://www.virustotal.com/api/v3/";
    private static final long POLLING_INTERVAL_MS = 20000; // 20 seconds
    private static final int MAX_POLLS = 15; // Max 5 minutes (15 * 20s)

    private final String apiKey;
    private final OkHttpClient client;
    private final ObjectMapper mapper;

    public VirusTotalAnalyzer() {
        this.apiKey = "c830faa612499becfca3247c5688cf38f4d4b6b98d518285abfee871a1432e92";

        this.client = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(60, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .build();
        this.mapper = new ObjectMapper();
    }

    public boolean isConfigured() {
        return this.apiKey != null;
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
            // --- MODIFICATION START ---
            // Read the body into a string variable *first*.
            String responseBody = response.body().string();

            if (!response.isSuccessful()) {
                LOGGER.error("VirusTotal Upload Response (Error): {}", responseBody); // Log error response
                throw new IOException("VirusTotal upload failed: " + response.code());
            }

            // Log the successful upload response
            LOGGER.info("VirusTotal Upload Response JSON: {}", responseBody);

            // Now parse the string you already logged
            JsonNode root = mapper.readTree(responseBody);
            // --- MODIFICATION END ---

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
                // --- MODIFICATION START ---
                // Read the body into a string variable *first*.
                String responseBody = response.body().string();

                if (!response.isSuccessful()) {
                    if (response.code() == 404) {
                        LOGGER.warn("VirusTotal analysis report not found yet. Retrying in {}s...", POLLING_INTERVAL_MS / 1000);
                        Thread.sleep(POLLING_INTERVAL_MS);
                        continue;
                    }
                    LOGGER.error("VirusTotal Report Response (Error): {}", responseBody); // Log error response
                    throw new IOException("VirusTotal report retrieval failed: " + response.code());
                }

                // Log the analysis poll response
                LOGGER.info("VirusTotal Analysis Response JSON: {}", responseBody);

                // Now parse the string you already logged
                JsonNode root = mapper.readTree(responseBody);
                // --- MODIFICATION END ---

                String status = root.path("data").path("attributes").path("status").asText();

                if ("completed".equals(status)) {
                    LOGGER.info("VirusTotal analysis complete.");
                    JsonNode stats = root.path("data").path("attributes").path("stats");
                    int maliciousCount = stats.path("malicious").asInt();
                    int suspiciousCount = stats.path("suspicious").asInt();

                    if (maliciousCount > 0 || suspiciousCount > 0) {
                        LOGGER.warn("[CRITICAL] VirusTotal scan result: MALICIOUS ({}) / SUSPICIOUS ({})", maliciousCount, suspiciousCount);
                        return true;
                    } else {
                        LOGGER.info("VirusTotal scan result: CLEAN");
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