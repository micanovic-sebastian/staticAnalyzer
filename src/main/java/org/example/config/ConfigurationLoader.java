package org.example.config;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.InputStream;

public class ConfigurationLoader {
    private static final ScanConfiguration configuration;

    static {
        try (InputStream is = ConfigurationLoader.class.getResourceAsStream("/config.json")) {
            if (is == null) {
                throw new RuntimeException("Cannot find config.json in classpath. Make sure it is in src/main/resources.");
            }
            ObjectMapper mapper = new ObjectMapper();
            configuration = mapper.readValue(is, ScanConfiguration.class);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load or parse config.json", e);
        }
    }

    public static ScanConfiguration getConfiguration() {
        return configuration;
    }
}