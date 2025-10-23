package org.example.config;

/**
 * Stellt einen einzelnen gefundenen Regelverstoß dar
 * Speichert Nachricht Zeilennummer und Schweregrad
 */
public class Violation {
    private final String message;
    private final long lineNumber;
    private final String severity;

    public Violation(String message, long lineNumber, String severity) {
        this.message = message;
        this.lineNumber = lineNumber;
        this.severity = severity;
    }

    /**
     * Erzeugt die Log-Ausgabe für diesen Verstoß
     * @return Ein formatierter String für das Log
     */
    @Override
    public String toString() {
        return String.format("[%s] Line %d: %s", severity.toUpperCase(), lineNumber, message);
    }
}
