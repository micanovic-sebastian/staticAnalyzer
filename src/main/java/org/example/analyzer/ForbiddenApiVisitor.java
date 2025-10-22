package org.example.analyzer;

import com.sun.source.tree.*;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreeScanner;
import org.example.config.ConfigurationLoader;
import org.example.config.ScanConfiguration;
import org.example.config.Violation;

import java.util.ArrayList;
import java.util.List;

public class ForbiddenApiVisitor extends TreeScanner<Void, Void> {

    // Fields for Violation-Constraints
    private final List<Violation> violations;
    private final CompilationUnitTree compilationUnit;
    private final SourcePositions sourcePositions;
    private final FileOperationAnalyzer fileAnalyzer;
    private final ScanConfiguration config = ConfigurationLoader.getConfiguration();

    // Fields for methods
    private int methodTimingCallCount = 0;

    // --- NEW: Fields for Entropy Calculation ---
    private final List<Double> identifierEntropies = new ArrayList<>();
    // Don't calculate entropy for very short names (like 'i', 'e', 'x')
    // as they are common in normal code and can skew the average.
    private static final int MIN_ENTROPY_LENGTH = 3;

    public ForbiddenApiVisitor(CompilationUnitTree compilationUnit, SourcePositions sourcePositions) {
        this.compilationUnit = compilationUnit;
        this.sourcePositions = sourcePositions;
        this.violations = new ArrayList<>();
        this.fileAnalyzer = new FileOperationAnalyzer(config);
    }

    public List<Violation> getViolations() {
        return violations;
    }

    public List<Double> getIdentifierEntropies() {
        return identifierEntropies;
    }

    private void checkAndStoreEntropy(String identifier) {
        if (identifier != null && identifier.length() >= MIN_ENTROPY_LENGTH) {
            double entropy = EntropyUtil.calculateShannonEntropy(identifier);
            identifierEntropies.add(entropy);
        }
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
        public Void visitNewClass(NewClassTree node, Void p) {
            // Check for BigInteger instantiation inside loop (for crypto-mining)
            if (node.getIdentifier().toString().equals("BigInteger")) {
                foundBigInteger = true;
            }



            return super.visitNewClass(node, p);
        }

        @Override
        public Void visitMethodInvocation(MethodInvocationTree node, Void p) {
            String methodSelect = node.getMethodSelect().toString();
            if (methodSelect.equals("System.nanoTime") || methodSelect.equals("System.currentTimeMillis")) {
                foundTimingCall = true;
            }
            // Check for MessageDigest usage inside loop (for crypto-mining)
            if (methodSelect.contains("MessageDigest.getInstance")) {
                foundMessageDigest = true;
            }
            return super.visitMethodInvocation(node, p);
        }
    }

    // Searches for loop patterns
    private void checkForLoopPatterns(StatementTree loopBody, Tree loopNode) {
        LoopBodyScanner loopScanner = new LoopBodyScanner();
        loopScanner.scan(loopBody, null);

        if (loopScanner.foundMessageDigest && loopScanner.foundBigInteger) {
            addViolation("Potential cryptomining pattern detected: Hashing algorithm and BigInteger math found inside a loop.", "HIGH", loopNode);
        }
        if (loopScanner.foundXorOperation) {
            addViolation("Loop contains XOR operations, often used for simple decryption.", "LOW", loopNode);
        }
        if (loopScanner.foundTimingCall) {
            addViolation("Timing call (System.nanoTime/currentTimeMillis) found inside a loop.", "MEDIUM", loopNode);
        }
    }

    @Override
    public Void visitClass(ClassTree node, Void p) {
        // --- NEW: Check entropy of Class/Interface name ---
        checkAndStoreEntropy(node.getSimpleName().toString());
        return super.visitClass(node, p);
    }

    @Override
    public Void visitMethod(MethodTree node, Void p) {
        // --- NEW: Check entropy of Method name ---
        // Don't check constructors, their name is always the class name
        if (!node.getName().toString().equals("<init>")) {
            checkAndStoreEntropy(node.getName().toString());
        }

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
        checkForLoopPatterns(node.getStatement(), node);
        return super.visitDoWhileLoop(node, p);
    }

    @Override
    public Void visitCase(CaseTree node, Void p) {
        return super.visitCase(node, p);
    }

    @Override
    public Void visitCatch(CatchTree node, Void p) {
        if (node.getBlock().getStatements().isEmpty()) {
            addViolation("Suspicious empty catch block. This may be used to suppress errors.", "LOW", node);
        }
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

        else if (className.equals("String")) {
            if (node.getArguments().size() == 1) {
                ExpressionTree arg = node.getArguments().get(0);

                // Case 1: new String(variableName)
                if (arg.getKind() == Tree.Kind.IDENTIFIER) {
                    addViolation("string creation from a variable. May be hiding obfuscated data.", "LOW", node);
                }
                // Case 2: new String(new byte[] { ... }) or new String(new char[] { ... })
                else if (arg.getKind() == Tree.Kind.NEW_ARRAY) {
                    NewArrayTree newArray = (NewArrayTree) arg;
                    String arrayType = newArray.getType().toString();
                    if (arrayType.equals("byte") || arrayType.equals("char")) {
                        if (newArray.getInitializers() != null && !newArray.getInitializers().isEmpty()) {
                            addViolation("Creation of string from byte[] or char[] array.", "MEDIUM", node);
                        }
                    }
                }
            }
        }

        return super.visitNewClass(node, p);
    }

    @Override
    public Void visitMethodInvocation(MethodInvocationTree node, Void p) {
        String methodSelect = node.getMethodSelect().toString();

        if (methodSelect.equals("System.nanoTime") || methodSelect.equals("System.currentTimeMillis")) {
            this.methodTimingCallCount++;
        }

        // --- NEW: Check for dynamic Class.forName ---
        if (methodSelect.equals("Class.forName") && !node.getArguments().isEmpty()) {
            if (node.getArguments().get(0).getKind() != Tree.Kind.STRING_LITERAL) {
                addViolation("Suspicious dynamic class loading: Class.forName() is called with a variable, not a string literal.", "HIGH", node);
            }
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
        // --- NEW: Check entropy of Variable name ---
        checkAndStoreEntropy(node.getName().toString());

        if (node.getInitializer() != null) {
            ExpressionTree initializer = node.getInitializer();
        }
        return super.visitVariable(node, p);
    }

    @Override
    public Void visitLiteral(LiteralTree node, Void p) {
        // We only care about String literals
        if (node.getValue() instanceof String) {
            String value = (String) node.getValue();

            // --- NEW: Check entropy of String literal ---
            checkAndStoreEntropy(value);

            // 1. Check for IP Addresses
            if (DenyList.IP_ADDRESS_PATTERN.matcher(value).find()) {
                addViolation("IP address found: " + value, "MEDIUM", node);
            }

            // 2. Check for Domains (with basic heuristics to reduce false positives)
            if (value.contains(".") && DenyList.DOMAIN_PATTERN.matcher(value).find()) {
                // Exclude common Java package prefixes and file paths
                if (!value.startsWith("java.") && !value.startsWith("org.") &&
                    !value.startsWith("com.") && !value.startsWith("javax.") &&
                    !value.startsWith("sun.") && !value.contains("/") &&
                    !value.contains("\\") && !value.endsWith(".java") &&
                    !value.endsWith(".xml") && !value.endsWith(".json"))
                {
                    addViolation("Hardcoded domain/string found: " + value, "MEDIUM", node);
                }
            }
        }
        return super.visitLiteral(node, p);
    }
}