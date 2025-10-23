package org.example.analyzer;

import com.sun.source.tree.*;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.TreeScanner;
import org.example.config.ConfigurationLoader;
import org.example.config.Rule;
import org.example.config.ScanConfiguration;
import org.example.config.Violation;

import java.util.ArrayList;
import java.util.List;
import java.util.function.BiPredicate;

/**
 * Dieser Visitor durchläuft den Java-Syntaxbaum (AST)
 * Er sucht nach verdächtigen und verbotenen Code-Mustern
 * Gefundene Verstöße (Violations) werden gesammelt
 * Die Regeln stammen aus der ScanConfiguration
 */
public class ForbiddenApiVisitor extends TreeScanner<Void, Void> {

    private final List<Violation> violations;
    private final CompilationUnitTree compilationUnit;
    private final SourcePositions sourcePositions;
    private final FileOperationAnalyzer fileAnalyzer;
    private final ScanConfiguration config = ConfigurationLoader.getConfiguration();

    // Zählt Timing-Aufrufe (zb System.nanoTime) innerhalb einer Methode
    private int methodTimingCallCount = 0;

    private final List<Double> identifierEntropies = new ArrayList<>();
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

    /**
     * Berechnet die Entropie für einen Bezeichner
     * Hohe Entropie deutet auf Verschleierung hin
     */
    private void checkAndStoreEntropy(String identifier) {
        if (identifier != null && identifier.length() >= MIN_ENTROPY_LENGTH) {
            double entropy = EntropyUtil.calculateShannonEntropy(identifier);
            identifierEntropies.add(entropy);
        }
    }

    /**
     * Hilfsmethode zum Erstellen und Speichern einer Violation
     * Holt die Zeilennummer für den AST-Knoten
     */
    private void addViolation(String message, String severity, Tree node) {
        long startPosition = sourcePositions.getStartPosition(compilationUnit, node);
        long lineNumber = compilationUnit.getLineMap().getLineNumber(startPosition);
        violations.add(new Violation(message, lineNumber, severity));
    }

    /**
     * Prüft einen Namen gegen eine Regelliste mit einer bestimmten Strategie
     * Fügt eine Violation hinzu wenn ein Treffer gefunden wurde
     *
     * @param nameToCheck Der zu prüfende String-Name (zb Import-Name Methoden-Name)
     * @param rules       Die Liste der Regeln gegen die geprüft wird
     * @param matchStrategy Ein BiPredicate das den Vergleich von nameToCheck und Regel-Pattern definiert
     * @param node        Der AST-Knoten für die Zeilennummer
     */
    private void checkRules(String nameToCheck, List<Rule> rules, BiPredicate<String, String> matchStrategy, Tree node) {
        if (rules == null) return; // Behandelt Fälle in denen eine Regelliste in der Config fehlt
        rules.stream()
             .filter(rule -> matchStrategy.test(nameToCheck, rule.pattern))
             .findFirst()
             .ifPresent(rule -> addViolation(rule.message + " (" + nameToCheck + ")", rule.severity, node));
    }


    /**
     * Ein spezialisierter Scanner der nur den Rumpf einer Schleife prüft
     * Sucht nach Mustern wie Krypto-Mining oder Timing-Angriffen
     */
    private static class LoopBodyScanner extends TreeScanner<Void, Void> {
        boolean foundMessageDigest = false;
        boolean foundBigInteger = false;
        boolean foundXorOperation = false;
        boolean foundTimingCall = false;

        @Override
        public Void visitBinary(BinaryTree node, Void p) {
            // Sucht nach XOR-Operationen
            if (node.getKind() == Tree.Kind.XOR) {
                foundXorOperation = true;
            }
            return super.visitBinary(node, p);
        }

        @Override
        public Void visitNewClass(NewClassTree node, Void p) {
            // Sucht nach BigInteger-Nutzung
            if (node.getIdentifier().toString().equals("BigInteger")) {
                foundBigInteger = true;
            }
            return super.visitNewClass(node, p);
        }

        @Override
        public Void visitMethodInvocation(MethodInvocationTree node, Void p) {
            String methodSelect = node.getMethodSelect().toString();
            // Sucht nach Timing-Aufrufen
            if (methodSelect.equals("System.nanoTime") || methodSelect.equals("System.currentTimeMillis")) {
                foundTimingCall = true;
            }
            // Sucht nach Hashing-Aufrufen
            if (methodSelect.contains("MessageDigest.getInstance")) {
                foundMessageDigest = true;
            }
            return super.visitMethodInvocation(node, p);
        }
    }

    /**
     * Startet den LoopBodyScanner für eine Schleife
     * Meldet Verstöße basierend auf den Funden des Scanners
     */
    private void checkForLoopPatterns(StatementTree loopBody, Tree loopNode) {
        LoopBodyScanner loopScanner = new LoopBodyScanner();
        loopScanner.scan(loopBody, null);

        // Krypto-Mining-Muster
        if (loopScanner.foundMessageDigest && loopScanner.foundBigInteger) {
            addViolation("Potential cryptomining pattern detected: Hashing algorithm and BigInteger math found inside a loop.", "HIGH", loopNode);
        }
        // Verschleierungs-Muster
        if (loopScanner.foundXorOperation) {
            addViolation("Loop contains XOR operations, often used for simple decryption.", "LOW", loopNode);
        }
        // Anti-Analyse-Muster
        if (loopScanner.foundTimingCall) {
            addViolation("Timing call (System.nanoTime/currentTimeMillis) found inside a loop.", "MEDIUM", loopNode);
        }
    }

    /**
     * Besucht eine Klassendefinition
     * Prüft Entropie des Klassennamens
     */
    @Override
    public Void visitClass(ClassTree node, Void p) {
        checkAndStoreEntropy(node.getSimpleName().toString());
        return super.visitClass(node, p);
    }

    /**
     * Besucht eine Methodendefinition
     */
    @Override
    public Void visitMethod(MethodTree node, Void p) {
        // Ignoriere Konstruktoren (die heißen <init>)
        if (!node.getName().toString().equals("<init>")) {
            checkAndStoreEntropy(node.getName().toString());
        }

        // Setze den Zähler für Timing-Aufrufe für jede Methode zurück
        this.methodTimingCallCount = 0;
        Void result = super.visitMethod(node, p); // Steigt in den Methodenrumpf ab

        // Prüft ob die Methode verdächtig viele Timing-Aufrufe hat
        // Dies deutet auf Anti-Debugging hin
        if (this.methodTimingCallCount >= 2) {
            addViolation("Suspicious anti-sandbox/debugging pattern: Method contains " + this.methodTimingCallCount + " calls to System.nanoTime/currentTimeMillis, suggesting a timing check.", "HIGH", node);
        }

        this.methodTimingCallCount = 0; // Zähler für die nächste Methode zurücksetzen
        return result;
    }

    /**
     * Prüft auf toten Code zb if(false)
     */
    @Override
    public Void visitIf(IfTree node, Void p) {
        if (node.getCondition() instanceof LiteralTree) {
            LiteralTree condition = (LiteralTree) node.getCondition();
            if (Boolean.FALSE.equals(condition.getValue())) {
                 addViolation("Suspicious dead code block (if(false)). May be used for anti-analysis.", "LOW", node);
            }
        }
        return super.visitIf(node, p);
    }

    /**
     * Prüft Schleifenrumpf auf Muster und die Bedingung auf toten Code
     */
    @Override
    public Void visitWhileLoop(WhileLoopTree node, Void p) {
        checkForLoopPatterns(node.getStatement(), node);
         if (node.getCondition() instanceof LiteralTree) {
            LiteralTree condition = (LiteralTree) node.getCondition();
            if (Boolean.FALSE.equals(condition.getValue())) {
                 addViolation("Suspicious dead code block (while(false)). May be used for anti-analysis.", "LOW", node);
            }
        }
        return super.visitWhileLoop(node, p);
    }


    /**
     * Prüft Schleifenrumpf auf Muster
     */
    @Override
    public Void visitForLoop(ForLoopTree node, Void p) {
        checkForLoopPatterns(node.getStatement(), node);
        return super.visitForLoop(node, p);
    }

    /**
     * Prüft Schleifenrumpf auf Muster und die Bedingung auf toten Code
     */
    @Override
    public Void visitDoWhileLoop(DoWhileLoopTree node, Void p) {
        checkForLoopPatterns(node.getStatement(), node);
        if (node.getCondition() instanceof LiteralTree) {
            LiteralTree condition = (LiteralTree) node.getCondition();
            if (Boolean.FALSE.equals(condition.getValue())) {
                 addViolation("Suspicious dead code block (do{...}while(false)). May be used for anti-analysis.", "LOW", node);
            }
        }
        return super.visitDoWhileLoop(node, p);
    }

    @Override
    public Void visitCase(CaseTree node, Void p) {
        return super.visitCase(node, p);
    }

    /**
     * Prüft auf leere Catch-Blöcke
     * Das kann ein Versuch sein Fehler zu verschleiern
     */
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


    /**
     * Besucht einen Import-Befehl
     */
    @Override
    public Void visitImport(ImportTree node, Void p) {
        String importName = node.getQualifiedIdentifier().toString();

        // Prüfe verbotene Packages
        checkRules(importName, config.forbiddenPackages, String::startsWith, node);

        // Prüfe verbotene Klassen
        checkRules(importName, config.forbiddenClasses, String::equals, node);

        // Prüfe verdächtige Klassen
        checkRules(importName, config.suspiciousClasses, String::equals, node);

        return super.visitImport(node, p);
    }


    /**
     * Besucht einen Konstruktor-Aufruf (zb new File(...))
     */
    @Override
    public Void visitNewClass(NewClassTree node, Void p) {

        String className = node.getIdentifier().toString();

        // Prüft auf verdächtige Datei-Pfade
        if (className.equals("File") || className.equals("FileInputStream") || className.equals("FileOutputStream")) {
            fileAnalyzer.findSuspiciousPathRule(node)
                    .ifPresent(rule -> addViolation(rule.message, rule.severity, node));
        }

        // Prüft auf String-Konstruktion aus Variablen oder Arrays
        // Oft genutzt um verschleierte Daten zu laden
        else if (className.equals("String")) {
            if (node.getArguments().size() == 1) {
                ExpressionTree arg = node.getArguments().get(0);
                if (arg.getKind() == Tree.Kind.IDENTIFIER) {
                    addViolation("string creation from a variable. May be hiding obfuscated data.", "LOW", node);
                }
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

    /**
     * Besucht einen Methoden-Aufruf
     */
    @Override
    public Void visitMethodInvocation(MethodInvocationTree node, Void p) {
        String methodSelect = node.getMethodSelect().toString();

        // Zählt Timing-Aufrufe innerhalb einer Methode
        if (methodSelect.equals("System.nanoTime") || methodSelect.equals("System.currentTimeMillis")) {
            this.methodTimingCallCount++;
        }

        // Prüft auf System-Fingerprinting
        if (methodSelect.equals("System.getProperty") || methodSelect.equals("System.getenv")) {
            if (!node.getArguments().isEmpty() && node.getArguments().get(0) instanceof LiteralTree) {
                LiteralTree arg = (LiteralTree) node.getArguments().get(0);
                if (arg.getValue() instanceof String) {
                    String propertyName = (String) arg.getValue();
                    if (DenyList.FINGERPRINTING_PROPERTIES.contains(propertyName)) {
                        addViolation("Suspicious system property access for fingerprinting: " + propertyName, "MEDIUM", node);
                    }
                }
            } else {
                 // Dynamischer Zugriff ist ebenfalls verdächtig
                 addViolation("Potentially suspicious dynamic access to system property/environment variable.", "LOW", node);
            }
        }


        // Prüft auf dynamisches Laden von Klassen
        if (methodSelect.equals("Class.forName") && !node.getArguments().isEmpty()) {
            if (node.getArguments().get(0).getKind() != Tree.Kind.STRING_LITERAL) {
                addViolation("Suspicious dynamic class loading: Class.forName() is called with a variable, not a string literal.", "HIGH", node);
            }
        }

        // Prüfe verbotene Methoden
        checkRules(methodSelect, config.forbiddenMethods, String::endsWith, node);

        // Prüfe Verschleierungs-Methoden
        checkRules(methodSelect, config.obfuscationMethods, String::endsWith, node);


        // Prüft Datei-Pfade bei NIO-Aufrufen
        if (methodSelect.startsWith("Files.write") || methodSelect.startsWith("Files.read")) {
            fileAnalyzer.findSuspiciousPathRule(node)
                    .ifPresent(rule -> addViolation(rule.message, rule.severity, node));
        }
        return super.visitMethodInvocation(node, p);
    }

    /**
     * Besucht eine Variablen-Deklaration
     * Prüft Entropie des Namens
     */
    @Override
    public Void visitVariable(VariableTree node, Void p) {
        checkAndStoreEntropy(node.getName().toString());
        return super.visitVariable(node, p);
    }

    /**
     * Besucht ein String-Literal (zb "text")
     */
    @Override
    public Void visitLiteral(LiteralTree node, Void p) {
        if (node.getValue() instanceof String) {
            String value = (String) node.getValue();
            // Prüft die Entropie des String-Inhalts
            checkAndStoreEntropy(value);

            String lowerValue = value.toLowerCase();
            // Prüft auf verdächtige Strings (VM-Namen Sandbox-Pfade etc)
            for (String suspicious : DenyList.SUSPICIOUS_FINGERPRINTING_STRINGS) {
                 if (lowerValue.contains(suspicious.toLowerCase())) {
                     addViolation("Suspicious string literal found (potential fingerprinting/evasion artifact): " + value, "LOW", node);
                     break;
                 }
            }

            // Prüft auf hartcodierte IP-Adressen
            if (DenyList.IP_ADDRESS_PATTERN.matcher(value).find()) {
                addViolation("IP address found: " + value, "MEDIUM", node);
            }

            // Prüft auf hartcodierte Domains
            // Filtert normale Java-Paketnamen und Dateiendungen heraus
            if (value.contains(".") && DenyList.DOMAIN_PATTERN.matcher(value).find()) {
                if (!value.startsWith("java.") && !value.startsWith("org.") &&
                        !value.startsWith("com.") && !value.startsWith("javax.") &&
                        !value.startsWith("sun.") && !value.contains("/") &&
                        !value.contains("\\") && !value.endsWith(".java") &&
                        !value.endsWith(".xml") && !value.endsWith(".json")) {
                    addViolation("Hardcoded domain/string found: " + value, "MEDIUM", node);
                }
            }
        }
        return super.visitLiteral(node, p);
    }
}

