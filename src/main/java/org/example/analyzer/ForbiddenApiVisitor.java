package org.example.analyzer;

import com.sun.source.tree.*;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreeScanner;
import org.example.analyzer.FileOperationAnalyzer;
import org.example.config.ConfigurationLoader;
import org.example.config.ScanConfiguration;
import org.example.config.Violation;

import java.util.ArrayList;
import java.util.List;

public class ForbiddenApiVisitor extends TreeScanner<Void, Void> {

    private final List<Violation> violations;
    private final CompilationUnitTree compilationUnit;
    private final SourcePositions sourcePositions;
    private final FileOperationAnalyzer fileAnalyzer;
    private final ScanConfiguration config = ConfigurationLoader.getConfiguration();
    private final TaintAnalyzer taintAnalyzer = new TaintAnalyzer();

    public ForbiddenApiVisitor(CompilationUnitTree compilationUnit, SourcePositions sourcePositions) {
        this.compilationUnit = compilationUnit;
        this.sourcePositions = sourcePositions;
        this.violations = new ArrayList<>();
        this.fileAnalyzer = new FileOperationAnalyzer(config);
    }

    public List<Violation> getViolations() {
        return violations;
    }

    private void addViolation(String message, String severity, Tree node) {
        long startPosition = sourcePositions.getStartPosition(compilationUnit, node);
        long lineNumber = compilationUnit.getLineMap().getLineNumber(startPosition);
        violations.add(new Violation(message, lineNumber, severity));
    }

    private static class LoopBodyScanner extends TreeScanner<Void, Void> {
        boolean foundMessageDigest = false;
        boolean foundBigInteger = false;
        boolean foundXorOperation = false; // Flag for obfuscation

        @Override
        public Void visitBinary(BinaryTree node, Void p) {
            if (node.getKind() == Tree.Kind.XOR) {
                foundXorOperation = true;
            }
            return super.visitBinary(node, p);
        }
        // ... other visit methods from previous implementation ...
    }

    // Helper to check for patterns in any kind of loop
    private void checkForLoopPatterns(StatementTree loopBody, Tree loopNode) {
        LoopBodyScanner loopScanner = new LoopBodyScanner();
        loopScanner.scan(loopBody, null);

        if (loopScanner.foundMessageDigest && loopScanner.foundBigInteger) {
            addViolation("Potential cryptomining pattern detected.", "HIGH", loopNode);
        }
        if (loopScanner.foundXorOperation) {
            addViolation("Potential string obfuscation: Loop contains XOR operations, often used for simple decryption.", "HIGH", loopNode);
        }
    }

    @Override
    public Void visitWhileLoop(WhileLoopTree node, Void p) {
        checkForLoopPatterns(node.getStatement(), node);
        return super.visitWhileLoop(node, p);
    }

    @Override
    public Void visitForLoop(ForLoopTree node, Void p) {
        checkForLoopPatterns(node.getStatement(), node);
        return super.visitForLoop(node, p);
    }

    @Override
    public Void visitImport(ImportTree node, Void p) {
        String importName = node.getQualifiedIdentifier().toString();

        config.forbiddenPackages.stream()
            .filter(rule -> importName.startsWith(rule.pattern))
            .findFirst()
            .ifPresent(rule -> addViolation(rule.message + " (" + importName + ")", rule.severity, node));

        config.forbiddenClasses.stream()
            .filter(rule -> importName.equals(rule.pattern))
            .findFirst()
            .ifPresent(rule -> addViolation(rule.message + " (" + importName + ")", rule.severity, node));

        config.suspiciousClasses.stream()
            .filter(rule -> importName.equals(rule.pattern))
            .findFirst()
            .ifPresent(rule -> addViolation(rule.message + " (" + importName + ")", rule.severity, node));

        return super.visitImport(node, p);
    }

    @Override
    public Void visitNewClass(NewClassTree node, Void p) {
        String className = node.getIdentifier().toString();
        if (className.equals("File") || className.equals("FileInputStream") || className.equals("FileOutputStream")) {
            fileAnalyzer.findSuspiciousPathRule(node)
                    .ifPresent(rule -> addViolation(rule.message, rule.severity, node));
        }
        return super.visitNewClass(node, p);
    }

    @Override
    public Void visitMethodInvocation(MethodInvocationTree node, Void p) {
        String methodSelect = node.getMethodSelect().toString();

        config.forbiddenMethods.stream()
            .filter(rule -> methodSelect.endsWith(rule.pattern))
            .findFirst()
            .ifPresent(rule -> addViolation(rule.message + " (" + methodSelect + ")", rule.severity, node));

        // Check for obfuscation methods
        config.obfuscationMethods.stream()
            .filter(rule -> methodSelect.endsWith(rule.pattern))
            .findFirst()
            .ifPresent(rule -> addViolation(rule.message + " (" + methodSelect + ")", rule.severity, node));

        taintAnalyzer.analyzeSink(node).ifPresent(violationMessage -> {
            addViolation(violationMessage, "CRITICAL", node);
        });

        if (methodSelect.startsWith("Files.write") || methodSelect.startsWith("Files.read")) {
            fileAnalyzer.findSuspiciousPathRule(node)
                    .ifPresent(rule -> addViolation(rule.message, rule.severity, node));
        }
        return super.visitMethodInvocation(node, p);
    }

    @Override
    public Void visitVariable(VariableTree node, Void p) {
        // Check if the variable is being initialized
        if (node.getInitializer() != null) {
            ExpressionTree initializer = node.getInitializer();

            // Case 1: Taint Source (e.g., String s = socket.getInputStream().read())
            if (initializer instanceof MethodInvocationTree) {
                taintAnalyzer.trackSource(node, (MethodInvocationTree) initializer);
            }
            // Case 2: Taint Propagation (e.g., String cmd = s)
            else {
                taintAnalyzer.propagateTaint(node, initializer);
            }
        }
        return super.visitVariable(node, p);
    }
}