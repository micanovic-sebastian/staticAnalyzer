package org.example.config;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.InputStream;

/**
 * Lädt die Scan-Konfiguration aus der config.json Datei
 * Die Konfiguration wird nur einmal beim Start geladen
 */
public class ConfigurationLoader {
    // Die einzige Instanz der Konfiguration
    private static final ScanConfiguration configuration;

    // Statischer Initialisierer wird beim Laden der Klasse ausgeführt
    static {
        try (InputStream is = ConfigurationLoader.class.getResourceAsStream("/config.json")) {
            if (is == null) {
                throw new RuntimeException("Cannot find config.json in classpath. Make sure it is in src/main/resources.");
            }
            // JSON-Datei mit Jackson parsen
            ObjectMapper mapper = new ObjectMapper();
            configuration = mapper.readValue(is, ScanConfiguration.class);
        } catch (Exception e) {
            // Fehler wenn die Konfiguration fehlt oder fehlerhaft ist
            throw new RuntimeException("Failed to load or parse config.json", e);
        }
    }

    /**
     * Gibt die global geladene Konfiguration zurück
     * @return Die ScanConfiguration Instanz
     */
    public static ScanConfiguration getConfiguration() {
        return configuration;
    }
}
