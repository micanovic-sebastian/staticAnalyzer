package org.example.analyzer;

import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.LiteralTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.NewClassTree;
import com.sun.source.tree.Tree;
import org.example.config.Rule;
import org.example.config.ScanConfiguration;

import java.util.List;
import java.util.Optional;

public class FileOperationAnalyzer {

    private final ScanConfiguration config;

    public FileOperationAnalyzer(ScanConfiguration config) {
        this.config = config;
    }

    public Optional<Rule> findSuspiciousPathRule(Tree node) {
        return extractStringArgument(node)
                .flatMap(this::findMatchingRule);
    }

    private Optional<Rule> findMatchingRule(String path) {
        // Normalisiere den Pfad für einen einfachen Abgleich
        String normalizedPath = path.toLowerCase().replace('\\', '/');
        return config.suspiciousFilePaths.stream()
                .filter(rule -> normalizedPath.contains(rule.pattern))
                .findFirst();
    }

    // Es wird das erste String-Argument aus einem Knoten extrahieren
    private Optional<String> extractStringArgument(Tree node) {
        List<? extends ExpressionTree> arguments = null;

        if (node instanceof NewClassTree) {
            // Behandelt Konstruktor-Aufrufe zb new File("...")
            arguments = ((NewClassTree) node).getArguments();
        } else if (node instanceof MethodInvocationTree) {
            // Behandelt Methoden-Aufrufe zb Paths.get("...")
            arguments = ((MethodInvocationTree) node).getArguments();
        }

        if (arguments != null && !arguments.isEmpty()) {
            // Wir prüfen nur das erste Argument
            ExpressionTree argument = arguments.get(0);
            if (argument instanceof LiteralTree) {
                Object value = ((LiteralTree) argument).getValue();
                if (value instanceof String) {
                    return Optional.of((String) value);
                }
            }
        }
        return Optional.empty();
    }
}

