package org.example.config;

public class Violation {
    private final String message;
    private final long lineNumber;
    private final String severity;

    public Violation(String message, long lineNumber, String severity) {
        this.message = message;
        this.lineNumber = lineNumber;
        this.severity = severity;
    }

    @Override
    public String toString() {
        return String.format("[%s] [VIOLATION] Line %d: %s", severity.toUpperCase(), lineNumber, message);
    }
}