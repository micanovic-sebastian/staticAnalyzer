package org.example.analyzer;

import com.sun.source.tree.*;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreeScanner;
import org.example.analyzer.FileOperationAnalyzer;
import org.example.config.ConfigurationLoader;
import org.example.config.ScanConfiguration;
import org.example.config.Violation;

import java.util.ArrayList;
import java.util.HashMap; // <-- ADDED
import java.util.List;
import java.util.Map; // <-- ADDED

public class ForbiddenApiVisitor extends TreeScanner<Void, Void> {

    private final List<Violation> violations;
    private final CompilationUnitTree compilationUnit;
    private final SourcePositions sourcePositions;
    private final FileOperationAnalyzer fileAnalyzer;
    private final ScanConfiguration config = ConfigurationLoader.getConfiguration();
    private final TaintAnalyzer taintAnalyzer = new TaintAnalyzer();

    // --- NEW: Fields for Cyclomatic Complexity ---
    private final Map<String, Integer> methodComplexities;
    private String currentClassName;
    private String currentMethodName;
    // --- END NEW ---

    public ForbiddenApiVisitor(CompilationUnitTree compilationUnit, SourcePositions sourcePositions) {
        this.compilationUnit = compilationUnit;
        this.sourcePositions = sourcePositions;
        this.violations = new ArrayList<>();
        this.fileAnalyzer = new FileOperationAnalyzer(config);
        // --- NEW: Initialize complexity fields ---
        this.methodComplexities = new HashMap<>();
        this.currentClassName = null;
        this.currentMethodName = null;
        // --- END NEW ---
    }

    public List<Violation> getViolations() {
        return violations;
    }

    // --- NEW: Getter for complexity results ---
    public Map<String, Integer> getMethodComplexities() {
        return methodComplexities;
    }
    // --- END NEW ---

    private void addViolation(String message, String severity, Tree node) {
        long startPosition = sourcePositions.getStartPosition(compilationUnit, node);
        long lineNumber = compilationUnit.getLineMap().getLineNumber(startPosition);
        violations.add(new Violation(message, lineNumber, severity));
    }

    // --- NEW: Helper to increment complexity for the current method ---
    private void incrementComplexity() {
        if (currentMethodName != null && currentClassName != null) {
            String key = currentClassName + "." + currentMethodName;
            methodComplexities.put(key, methodComplexities.get(key) + 1);
        }
    }
    // --- END NEW ---

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

    // --- NEW: Track class name ---
    @Override
    public Void visitClass(ClassTree node, Void p) {
        // Store class name to create unique method keys (e.g., "MyClass.myMethod")
        this.currentClassName = node.getSimpleName().toString();
        return super.visitClass(node, p);
    }
    // --- END NEW ---

    // --- NEW: Track method entry/exit and set base complexity ---
    @Override
    public Void visitMethod(MethodTree node, Void p) {
        this.currentMethodName = node.getName().toString();
        // Constructors have a special name "<init>", this is fine
        if (this.currentClassName != null) {
            String key = this.currentClassName + "." + this.currentMethodName;
            this.methodComplexities.put(key, 1); // Start with base complexity of 1
        }

        // Scan the method body
        Void result = super.visitMethod(node, p);

        this.currentMethodName = null; // Exit the method scope
        return result;
    }
    // --- END NEW ---

    // --- NEW: Overrides for all decision points ---

    @Override
    public Void visitIf(IfTree node, Void p) {
        incrementComplexity(); // +1 for "if"
        return super.visitIf(node, p);
    }

    @Override
    public Void visitWhileLoop(WhileLoopTree node, Void p) {
        incrementComplexity(); // +1 for "while"
        checkForLoopPatterns(node.getStatement(), node); // Keep existing logic
        return super.visitWhileLoop(node, p);
    }

    @Override
    public Void visitForLoop(ForLoopTree node, Void p) {
        incrementComplexity(); // +1 for "for"
        checkForLoopPatterns(node.getStatement(), node); // Keep existing logic
        return super.visitForLoop(node, p);
    }

    @Override
    public Void visitDoWhileLoop(DoWhileLoopTree node, Void p) {
        incrementComplexity(); // +1 for "do-while"
        return super.visitDoWhileLoop(node, p);
    }

    @Override
    public Void visitCase(CaseTree node, Void p) {
        // "default" case doesn't add complexity
        if (node.getExpression() != null) {
            incrementComplexity(); // +1 for "case"
        }
        return super.visitCase(node, p);
    }

    @Override
    public Void visitCatch(CatchTree node, Void p) {
        incrementComplexity(); // +1 for "catch"
        return super.visitCatch(node, p);
    }

    @Override
    public Void visitConditionalExpression(ConditionalExpressionTree node, Void p) {
        incrementComplexity(); // +1 for ternary operator (?:)
        return super.visitConditionalExpression(node, p);
    }

    @Override
    public Void visitBinary(BinaryTree node, Void p) {
        // +1 for each "&&" or "||"
        if (node.getKind() == Tree.Kind.AND || node.getKind() == Tree.Kind.OR) {
            incrementComplexity();
        }
        return super.visitBinary(node, p);
    }
    // --- END NEW ---


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