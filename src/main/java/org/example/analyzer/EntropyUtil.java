package org.example.analyzer;

import java.util.HashMap;
import java.util.Map;

/**
 * eine Hilfsklasse zur Berechnung der Shannon-Entropie eines Strings
 * Entropie ist ein Maß für Zufälligkeit oder Unvorhersehbarkeit
 * Strings mit hoher Entropie sind typisch für verschleierte oder verschlüsselte Daten
 * - "password" -> Niedrige Entropie (1.98)
 * - "aGf8Kk9qX" -> Hohe Entropie (3.17)
 */
public class EntropyUtil {

    /**
     * berechnet die Shannon-Entropie für einen gegebenen String
     * @param s der Input-String
     * @return der Entropie-Wert (in Bits)
     */
    public static double calculateShannonEntropy(String s) {
        if (s == null || s.isEmpty()) {
            return 0.0;
        }

        // 1 zähle die Zeichenhäufigkeit
        Map<Character, Integer> charCounts = new HashMap<>();
        for (char c : s.toCharArray()) {
            charCounts.put(c, charCounts.getOrDefault(c, 0) + 1);
        }

        // 2 berechne die Entropie
        double entropy = 0.0;
        int length = s.length();
        for (int count : charCounts.values()) {
            // Wahrscheinlichkeit des Zeichens
            double p = (double) count / length;
            // Entropie-Formel: -p * log2(p)
            entropy -= p * (Math.log(p) / Math.log(2));
        }

        return entropy;
    }
}

