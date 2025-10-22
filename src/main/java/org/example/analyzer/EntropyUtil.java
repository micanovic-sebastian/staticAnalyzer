package org.example.analyzer;

import java.util.HashMap;
import java.util.Map;

/**
 * A utility class to calculate the Shannon entropy of a string.
 * Entropy is a measure of randomness or unpredictability.
 * High-entropy strings are typical in obfuscated or encrypted data.
 * - "password" -> Low Entropy (1.98)
 * - "aGf8Kk9qX" -> High Entropy (3.17)
 */
public class EntropyUtil {

    /**
     * Calculates the Shannon entropy for a given string.
     * @param s The input string.
     * @return The entropy value (in bits).
     */
    public static double calculateShannonEntropy(String s) {
        if (s == null || s.isEmpty()) {
            return 0.0;
        }

        // 1. Count character frequencies
        Map<Character, Integer> charCounts = new HashMap<>();
        for (char c : s.toCharArray()) {
            charCounts.put(c, charCounts.getOrDefault(c, 0) + 1);
        }

        // 2. Calculate entropy
        double entropy = 0.0;
        int length = s.length();
        for (int count : charCounts.values()) {
            // probability of character
            double p = (double) count / length;
            // entropy formula: -p * log2(p)
            entropy -= p * (Math.log(p) / Math.log(2));
        }

        return entropy;
    }
}