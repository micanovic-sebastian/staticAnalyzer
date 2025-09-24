package org.example;

import com.sun.source.tree.ExpressionTree;
import com.sun.source.tree.LiteralTree;
import com.sun.source.tree.MethodInvocationTree;
import com.sun.source.tree.NewClassTree;
import com.sun.source.tree.Tree;
import java.util.List;
import java.util.Optional;

public class FileOperationAnalyzer {

    /**
     * Analyzes a file operation node (like "new File(path)") to see if the path is suspicious.
     * @param node The AST node representing the file operation.
     * @return An Optional containing a violation message if the path is suspicious.
     */
    public Optional<String> analyze(Tree node) {
        Optional<String> pathArgument = extractStringArgument(node);

        if (pathArgument.isPresent()) {
            String path = pathArgument.get();
            if (isPathSuspicious(path)) {
                return Optional.of("Suspicious file path access: " + path);
            }
        }
        // Note: If the path isn't a simple string (e.g., a variable), this check is skipped.
        // A more advanced analyzer would need to trace the variable's origin.
        return Optional.empty();
    }

    /**
     * Checks if a given file path matches any of our suspicious patterns.
     */
    private boolean isPathSuspicious(String path) {
        String normalizedPath = path.toLowerCase().replace('\\', '/');
        for (String suspiciousPattern : DenyList.SUSPICIOUS_FILE_PATHS) {
            if (normalizedPath.contains(suspiciousPattern)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extracts the first string literal argument from a method call or constructor.
     */
    private Optional<String> extractStringArgument(Tree node) {
        List<? extends ExpressionTree> arguments = null;

        if (node instanceof NewClassTree) {
            arguments = ((NewClassTree) node).getArguments();
        } else if (node instanceof MethodInvocationTree) {
            arguments = ((MethodInvocationTree) node).getArguments();
        }

        if (arguments != null && !arguments.isEmpty()) {
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