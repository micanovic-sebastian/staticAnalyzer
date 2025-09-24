package org.example.analyzer;

import com.sun.source.tree.*;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreeScanner;
import java.util.ArrayList;
import java.util.List;

/**
 * A TreeScanner that visits every node in a Java AST to find suspicious
 * or forbidden API calls based on a deny list and behavioral patterns.
 */
public class ForbiddenApiVisitor extends TreeScanner<Void, Void> {

    private final List<String> violations;
    private final CompilationUnitTree compilationUnit;
    private final SourcePositions sourcePositions;
    private final FileOperationAnalyzer fileAnalyzer;
    private final TaintAnalyzer taintAnalyzer; // Add a field for the new analyzer

    public ForbiddenApiVisitor(CompilationUnitTree compilationUnit, SourcePositions sourcePositions, TaintAnalyzer taintAnalyzer) {
        this.compilationUnit = compilationUnit;
        this.sourcePositions = sourcePositions;
        this.taintAnalyzer = taintAnalyzer;
        this.violations = new ArrayList<>();
        this.fileAnalyzer = new FileOperationAnalyzer(); // Handles file path analysis
    }

    /**
     * Returns the list of all violations found during the scan.
     */
    public List<String> getViolations() {
        return violations;
    }

    /**
     * Helper method to format and add a violation message with its line number.
     */
    private void addViolation(String message, Tree node) {
        long startPosition = sourcePositions.getStartPosition(compilationUnit, node);
        long lineNumber = compilationUnit.getLineMap().getLineNumber(startPosition);
        violations.add(String.format("[VIOLATION] Line %d: %s", lineNumber, message));
    }


    // --- Private Inner Class for Cryptomining & Obfuscation Patterns ---
    private static class LoopBodyScanner extends TreeScanner<Void, Void> {
        boolean foundMessageDigest = false;
        boolean foundBigInteger = false;
        boolean foundXorOperation = false; // New flag for obfuscation

        @Override
        public Void visitBinary(BinaryTree node, Void p) {
            // Check if the operator is a bitwise XOR
            if (node.getKind() == Tree.Kind.XOR) {
                foundXorOperation = true;
            }
            return super.visitBinary(node, p);
        }

        @Override
        public Void visitMethodInvocation(MethodInvocationTree node, Void p) {
            String methodSelect = node.getMethodSelect().toString();
            if (methodSelect.contains("MessageDigest.getInstance") || methodSelect.contains(".digest")) {
                foundMessageDigest = true;
            }
            if (methodSelect.contains(".compareTo")) {
                foundBigInteger = true;
            }
            return super.visitMethodInvocation(node, p);
        }

        @Override
        public Void visitNewClass(NewClassTree node, Void p) {
            if (node.getIdentifier().toString().equals("BigInteger")) {
                foundBigInteger = true;
            }
            return super.visitNewClass(node, p);
        }
    }

    // --- Overridden visit Methods ---

    @Override
    public Void visitImport(ImportTree node, Void p) {
        String importName = node.getQualifiedIdentifier().toString();

        if (DenyList.FORBIDDEN_PACKAGES.stream().anyMatch(importName::startsWith)) {
            addViolation("Forbidden package import: " + importName, node);
        }
        if (DenyList.FORBIDDEN_CLASSES.contains(importName)) {
            addViolation("Forbidden class import: " + importName, node);
        }
        if (DenyList.SUSPICIOUS_CLASSES.contains(importName)) {
            addViolation("Suspicious class import: " + importName, node);
        }
        return super.visitImport(node, p);
    }

    @Override
    public Void visitForLoop(ForLoopTree node, Void p) {
        checkForLoopPatterns(node.getStatement(), node);
        return super.visitForLoop(node, p);
    }

    @Override
    public Void visitWhileLoop(WhileLoopTree node, Void p) {
        checkCryptoMiningOperations(node);
        checkForLoopPatterns(node.getStatement(), node);
        return super.visitWhileLoop(node, p);
    }

    private void checkCryptoMiningOperations(WhileLoopTree node) {
        // --- Cryptomining Detection ---
        LoopBodyScanner loopScanner = new LoopBodyScanner();
        loopScanner.scan(node.getStatement(), null);

        if (loopScanner.foundMessageDigest && loopScanner.foundBigInteger) {
            addViolation("Potential cryptomining pattern: High-intensity hashing and BigInteger math inside a while loop.",
                         node);
        }
    }

    @Override
    public Void visitNewClass(NewClassTree node, Void p) {
        String className = node.getIdentifier().toString();

        // --- File Operation Analysis ---
        if (className.equals("File") || className.equals("FileInputStream") || className.equals("FileOutputStream")) {
            fileAnalyzer.analyze(node)
                    .ifPresent(violationMessage -> addViolation(violationMessage, node));
        }
        return super.visitNewClass(node, p);
    }

    @Override
    public Void visitMethodInvocation(MethodInvocationTree node, Void p) {
        String methodSelect = node.getMethodSelect().toString();

        // --- Base64 Obfuscation Detection ---
        if (DenyList.OBFUSCATION_METHODS.stream().anyMatch(methodSelect::endsWith)) {
            addViolation("Suspicious method call for de-obfuscation: " + methodSelect, node);
        }


        // --- Original Forbidden Method Calls ---
        if (DenyList.FORBIDDEN_METHODS.stream().anyMatch(methodSelect::endsWith)) {
            addViolation("Forbidden method call detected: " + methodSelect, node);
        }

        // --- Taint Analysis: Check for sensitive sinks ---
        taintAnalyzer.analyzeSink(node)
                     .ifPresent(violationMessage -> addViolation(violationMessage, node));

        // --- File Operation Analysis ---
        if (methodSelect.startsWith("Files.write") || methodSelect.startsWith("Files.read")) {
            fileAnalyzer.analyze(node)
                    .ifPresent(violationMessage -> addViolation(violationMessage, node));
        }
        return super.visitMethodInvocation(node, p);
    }

        /**
     * Overridden to track variable declarations and assignments for taint propagation.
     */
    @Override
    public Void visitVariable(VariableTree node, Void p) {
        ExpressionTree initializer = node.getInitializer();
        if (initializer != null) {
            // Case 1: Tainting from a source method call
            // e.g., String cmd = socket.getInputStream().read();
            if (initializer instanceof MethodInvocationTree) {
                taintAnalyzer.trackSource(node, (MethodInvocationTree) initializer);
            }
            // Case 2: Propagating taint from another variable
            // e.g., String anotherCmd = cmd;
            else if (initializer instanceof IdentifierTree) {
                taintAnalyzer.propagateTaint(node, initializer);
            }
        }
        return super.visitVariable(node, p);
    }

    // This method is now triggered by for loops as well.
    private void checkForLoopPatterns(StatementTree loopBody, Tree loopNode) {
        LoopBodyScanner loopScanner = new LoopBodyScanner();
        loopScanner.scan(loopBody, null);

        // Cryptomining check
        if (loopScanner.foundMessageDigest && loopScanner.foundBigInteger) {
            addViolation("Potential cryptomining pattern: High-intensity hashing and BigInteger math inside a loop.", loopNode);
        }

        // XOR Obfuscation check
        if (loopScanner.foundXorOperation) {
            addViolation("Potential string obfuscation: Loop contains XOR operations, often used for simple decryption.", loopNode);
        }
    }

        /**
     * Overridden to inspect every literal (constant) value in the code
     * for suspicious hardcoded values like IP addresses or ports.
     */
    @Override
    public Void visitLiteral(LiteralTree node, Void p) {
        Object value = node.getValue();

        // Check for suspicious string literals (e.g., IP addresses)
        if (value instanceof String) {
            String stringValue = (String) value;
            if (DenyList.IP_ADDRESS_PATTERN.matcher(stringValue).matches()) {
                // To reduce false positives, ignore the common localhost IP.
                if (!"127.0.0.1".equals(stringValue)) {
                    addViolation("Suspicious hardcoded IP address found: " + stringValue, node);
                }
            }
        }
        // Check for suspicious integer literals (e.g., malware ports)
        else if (value instanceof Integer) {
            Integer intValue = (Integer) value;
            if (DenyList.SUSPICIOUS_PORTS.contains(intValue)) {
                addViolation("Suspicious hardcoded port number found: " + intValue, node);
            }
        }

        return super.visitLiteral(node, p);
    }


}