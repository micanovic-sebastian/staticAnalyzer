package org.example.config;

import org.example.config.Rule;

import java.util.List;

// Represents the entire config.json structure
public class ScanConfiguration {
    public List<Rule> forbiddenPackages;
    public List<Rule> forbiddenClasses;
    public List<Rule> forbiddenMethods;
    public List<Rule> suspiciousClasses;
    public List<Rule> suspiciousFilePaths;
    public List<Rule> obfuscationMethods; // <-- ADD THIS LINE
}