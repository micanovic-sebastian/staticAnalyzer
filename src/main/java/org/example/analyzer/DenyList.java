package org.example.analyzer;

import java.util.Set;
import java.util.regex.Pattern;

public class DenyList {

        /**
     * Regex patterns for detecting suspicious string literals.
     */
    public static final Pattern IP_ADDRESS_PATTERN =
        Pattern.compile("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b");

    /**
     * Regex patterns for detecting suspicious domains.
     * This is a simple regex and might have false positives.
     */
    public static final Pattern DOMAIN_PATTERN =
        Pattern.compile("\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,6}\\b");

}