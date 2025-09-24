package org.example;

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

    public ForbiddenApiVisitor(CompilationUnitTree compilationUnit, SourcePositions sourcePositions) {
        this.compilationUnit = compilationUnit;
        this.sourcePositions = sourcePositions;
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

    // --- Private Inner Class for Cryptomining Pattern ---

    /**
     * A specialized scanner to check only a loop's body for the cryptomining pattern.
     */
    private static class LoopBodyScanner extends TreeScanner<Void, Void> {
        boolean foundMessageDigest = false;
        boolean foundBigInteger = false;

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
    public Void visitWhileLoop(WhileLoopTree node, Void p) {
        // --- Cryptomining Detection ---
        LoopBodyScanner loopScanner = new LoopBodyScanner();
        loopScanner.scan(node.getStatement(), null);

        if (loopScanner.foundMessageDigest && loopScanner.foundBigInteger) {
            addViolation("Potential cryptomining pattern: High-intensity hashing and BigInteger math inside a while loop.", node);
        }
        return super.visitWhileLoop(node, p);
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

        // --- Original Forbidden Method Calls ---
        if (DenyList.FORBIDDEN_METHODS.stream().anyMatch(methodSelect::endsWith)) {
            addViolation("Forbidden method call detected: " + methodSelect, node);
        }

        // --- File Operation Analysis ---
        if (methodSelect.startsWith("Files.write") || methodSelect.startsWith("Files.read")) {
            fileAnalyzer.analyze(node)
                    .ifPresent(violationMessage -> addViolation(violationMessage, node));
        }
        return super.visitMethodInvocation(node, p);
    }
}