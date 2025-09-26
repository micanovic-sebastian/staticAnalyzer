package org.example.analyzer;

import org.example.config.ConfigurationLoader;
import org.example.config.Rule;
import org.example.config.ScanConfiguration;

import java.net.URL;
import java.net.URLClassLoader;
import java.util.HashSet;
import java.util.Set;

public class SecureClassLoader extends URLClassLoader {

    private final Set<String> forbiddenClasses;
    private final Set<String> forbiddenPackages; // <-- ADD THIS SET

    public SecureClassLoader(URL[] urls, ClassLoader parent) {
        super(urls, parent);
        this.forbiddenClasses = new HashSet<>();
        this.forbiddenPackages = new HashSet<>(); // <-- INITIALIZE THE SET
        loadForbiddenRules();
        System.out.println("Sandbox: SecureClassLoader initialized. Forbidden rules loaded.");
    }

    private void loadForbiddenRules() {
        ScanConfiguration config = ConfigurationLoader.getConfiguration();
        for (Rule rule : config.forbiddenClasses) {
            forbiddenClasses.add(rule.pattern);
        }
        for (Rule rule : config.suspiciousClasses) {
            forbiddenClasses.add(rule.pattern);
        }
        // Load the package rules into the new set
        for (Rule rule : config.forbiddenPackages) {
            forbiddenPackages.add(rule.pattern);
        }
    }

    @Override
    public Class<?> loadClass(String name) throws ClassNotFoundException {
        // 1. Perform the security checks FIRST.

        // Check against the forbidden packages list
        for (String forbiddenPackage : forbiddenPackages) {
            if (name.startsWith(forbiddenPackage)) {
                throw new ClassNotFoundException("Security Violation: Access to forbidden package '" + forbiddenPackage + "' is blocked.");
            }
        }

        // Check against the forbidden classes list
        if (forbiddenClasses.contains(name)) {
            throw new ClassNotFoundException("Security Violation: Access to forbidden class " + name + " is blocked.");
        }

        // 2. If all checks pass, proceed with the normal loading logic.
        synchronized (getClassLoadingLock(name)) {
            Class<?> loadedClass = findLoadedClass(name);
            if (loadedClass != null) {
                return loadedClass;
            }

            if (name.startsWith("java.") || name.startsWith("javax.") || name.startsWith("sun.")) {
                return super.loadClass(name);
            }

            try {
                loadedClass = findClass(name);
                if (loadedClass != null) {
                    return loadedClass;
                }
            } catch (ClassNotFoundException e) {
                // Not found locally, which is fine.
            }

            return super.loadClass(name);
        }
    }
}