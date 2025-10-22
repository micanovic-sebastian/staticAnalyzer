package org.example.analyzer;

import com.sun.source.tree.*;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreeScanner;
import org.example.analyzer.FileOperationAnalyzer;
import org.example.config.ConfigurationLoader;
import org.example.config.ScanConfiguration;
import org.example.config.Violation;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ForbiddenApiVisitor extends TreeScanner<Void, Void> {

    // Felder für Violation-Contraints
    private final List<Violation> violations;
    private final CompilationUnitTree compilationUnit;
    private final SourcePositions sourcePositions;
    private final FileOperationAnalyzer fileAnalyzer;
    private final ScanConfiguration config = ConfigurationLoader.getConfiguration();

    // Felder für Methoden
    private int methodTimingCallCount = 0;


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
        boolean foundXorOperation = false;
        boolean foundTimingCall = false;

        @Override
        public Void visitBinary(BinaryTree node, Void p) {
            if (node.getKind() == Tree.Kind.XOR) {
                foundXorOperation = true;
            }
            return super.visitBinary(node, p);
        }

        @Override
        public Void visitMethodInvocation(MethodInvocationTree node, Void p) {
            String methodSelect = node.getMethodSelect().toString();
            if (methodSelect.equals("System.nanoTime") || methodSelect.equals("System.currentTimeMillis")) {
                foundTimingCall = true;
            }
            return super.visitMethodInvocation(node, p);
        }
    }

    // Sucht nach Schleifen
    private void checkForLoopPatterns(StatementTree loopBody, Tree loopNode) {
        LoopBodyScanner loopScanner = new LoopBodyScanner();
        loopScanner.scan(loopBody, null);

        if (loopScanner.foundMessageDigest && loopScanner.foundBigInteger) {
            addViolation("Potential cryptomining pattern detected.", "HIGH", loopNode);
        }
        if (loopScanner.foundXorOperation) {
            addViolation("Potential string obfuscation: Loop contains XOR operations, often used for simple decryption.", "HIGH", loopNode);
        }
        if (loopScanner.foundTimingCall) {
            addViolation("Suspicious anti-sandbox/debugging pattern: Timing call (System.nanoTime/currentTimeMillis) found inside a loop.", "HIGH", loopNode);
        }
    }

    @Override
    public Void visitClass(ClassTree node, Void p) {
        return super.visitClass(node, p);
    }

    @Override
    public Void visitMethod(MethodTree node, Void p) {
        this.methodTimingCallCount = 0; // Reset for this method

        Void result = super.visitMethod(node, p);

        if (this.methodTimingCallCount >= 2) {
             addViolation("Suspicious anti-sandbox/debugging pattern: Method contains " + this.methodTimingCallCount + " calls to System.nanoTime/currentTimeMillis, suggesting a timing check.", "HIGH", node);
        }

        this.methodTimingCallCount = 0; // Clear count
        return result;
    }

    @Override
    public Void visitIf(IfTree node, Void p) {
        return super.visitIf(node, p);
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
    public Void visitDoWhileLoop(DoWhileLoopTree node, Void p) {
        return super.visitDoWhileLoop(node, p);
    }

    @Override
    public Void visitCase(CaseTree node, Void p) {
        return super.visitCase(node, p);
    }

    @Override
    public Void visitCatch(CatchTree node, Void p) {
        return super.visitCatch(node, p);
    }

    @Override
    public Void visitConditionalExpression(ConditionalExpressionTree node, Void p) {
        return super.visitConditionalExpression(node, p);
    }

    @Override
    public Void visitBinary(BinaryTree node, Void p) {
        return super.visitBinary(node, p);
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

        if (methodSelect.equals("System.nanoTime") || methodSelect.equals("System.currentTimeMillis")) {
            this.methodTimingCallCount++;
        }

        config.forbiddenMethods.stream()
            .filter(rule -> methodSelect.endsWith(rule.pattern))
            .findFirst()
            .ifPresent(rule -> addViolation(rule.message + " (" + methodSelect + ")", rule.severity, node));

        config.obfuscationMethods.stream()
            .filter(rule -> methodSelect.endsWith(rule.pattern))
            .findFirst()
            .ifPresent(rule -> addViolation(rule.message + " (" + methodSelect + ")", rule.severity, node));



        if (methodSelect.startsWith("Files.write") || methodSelect.startsWith("Files.read")) {
            fileAnalyzer.findSuspiciousPathRule(node)
                    .ifPresent(rule -> addViolation(rule.message, rule.severity, node));
        }
        return super.visitMethodInvocation(node, p);
    }

    @Override
    public Void visitVariable(VariableTree node, Void p) {
        if (node.getInitializer() != null) {
            ExpressionTree initializer = node.getInitializer();

        }
        return super.visitVariable(node, p);
    }
}