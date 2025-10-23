package org.example.config;

/**
 * Definiert eine einzelne Regel aus der config.json
 * Dient als Datencontainer für Jackson
 */
public class Rule {
    // Das Muster wonach gesucht wird (zb ein Klassenname oder Pfad)
    public String pattern;
    // Die Schwere des Verstoßes (zb LOW MEDIUM HIGH)
    public String severity;
    // Die Nachricht die beim Verstoß geloggt wird
    public String message;
}
