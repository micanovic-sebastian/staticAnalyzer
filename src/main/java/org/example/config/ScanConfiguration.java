package org.example.config;

import java.util.List;

/**
 * Enthält alle Regellisten die aus der config.json geladen wurden
 * Dient als Datencontainer für Jackson
 */
public class ScanConfiguration {
    public List<Rule> forbiddenPackages;
    public List<Rule> forbiddenClasses;
    public List<Rule> forbiddenMethods;
    public List<Rule> suspiciousClasses;
    public List<Rule> suspiciousFilePaths;
    public List<Rule> obfuscationMethods;
}
