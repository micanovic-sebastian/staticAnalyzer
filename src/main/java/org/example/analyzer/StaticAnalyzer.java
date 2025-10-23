package org.example.analyzer;

import com.sun.source.tree.CompilationUnitTree;
import com.sun.source.util.JavacTask;
import com.sun.source.util.SourcePositions;
import com.sun.source.util.Trees;
import org.apache.logging.log4j.ThreadContext;
import org.example.config.Violation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Die Hauptklasse für die statische Code-Analyse
 * Parst Java-Dateien zu einem AST und lässt den ForbiddenApiVisitor darüber laufen
 * Zusätzlich integriert wird die VirusTotal-Prüfung
 */
public class StaticAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(StaticAnalyzer.class);

    // Ab diesem Entropie-Wert gilt ein Projekt als potenziell verschleiert
    private static final double ENTROPY_OBUFSCATION_THRESHOLD = 5;
    private static final DecimalFormat df = new DecimalFormat("0.00");

    // Definiert die verschiedenen Modi für die VirusTotal-Prüfung
    private enum VtMode {
        OFF,        // Kein VT-Scan
        HASH_ONLY,  // Nur die Hashes einzelner Dateien prüfen
        ZIP_ONLY,   // Nur das ZIP-Archiv hochladen
        DEFAULT     // Zuerst Hashes prüfen dann ZIP hochladen falls unbekannt
    }

    public static void main(String[] args) throws IOException {

        // Argumente parsen
        String inputPath = null;
        VtMode vtMode = VtMode.DEFAULT; // Standard-Verhalten für VT
        String logFileSetting = null; // null = Standard-Route (DefaultFile)
        String vtModeStr = null;
        boolean unrecognizedArg = false;
        String usage = "Usage: java StaticAnalyzer <Path> [vt-mode=off|hash|zip] [log=path/to/file.log|none]";

        for (String arg : args) {
            if (arg.startsWith("vt-mode=")) {
                vtModeStr = arg.substring("vt-mode=".length()).toLowerCase();
                switch (vtModeStr) {
                    case "off":
                        vtMode = VtMode.OFF;
                        break;
                    case "hash":
                        vtMode = VtMode.HASH_ONLY;
                        break;
                    case "zip":
                        vtMode = VtMode.ZIP_ONLY;
                        break;
                    default:
                        // Fehler-Logging wird zurückgestellt bis der ThreadContext gesetzt ist
                        break;
                }
            } else if (arg.startsWith("log=")) {
                logFileSetting = arg.substring("log=".length());
            } else if (inputPath == null) {
                // Das erste Argument ohne Präfix ist der Pfad
                inputPath = arg;
            } else {
                // Zu viele Argumente
                unrecognizedArg = true;
            }
        }

        // ThreadContext für das Logging setzen
        // Das muss vor der ersten Log-Nachricht passieren
        if (logFileSetting != null) {
            ThreadContext.put("logFile", logFileSetting);
        }
        // Wenn logFileSetting null ist, bleibt der ThreadContext leer
        // log4j2.xml leitet dann zur "DefaultFile"-Route

        // Jetzt kann man Fehler loggen
        if (args.length == 0) {
            LOGGER.error(usage);
            return;
        }

        if (inputPath == null) {
            LOGGER.error("No path specified. " + usage);
            return;
        }

        if (unrecognizedArg) {
             LOGGER.error("Too many arguments. " + usage);
             return;
        }

        if (vtModeStr != null && !List.of("off", "hash", "zip").contains(vtModeStr)) {
             LOGGER.error("Invalid vt-mode specified: {}. Valid options are off, hash, zip.", vtModeStr);
             return;
        }
        // Ende des Argument-Parsings


        File inputFile = new File(inputPath);
        if (!inputFile.exists()) {
            LOGGER.error("The path does not exist: {}", inputPath);
            return;
        }

        List<File> filesToAnalyze;
        if (inputFile.isDirectory()) {
            // Wenn es ein Verzeichnis ist alle .java-Dateien darin sammeln
            LOGGER.info("Scanning directory: {}", inputPath);
            try (Stream<Path> walk = Files.walk(inputFile.toPath())) {
                filesToAnalyze = walk
                        .filter(Files::isRegularFile)
                        .filter(p -> p.toString().endsWith(".java"))
                        .map(Path::toFile)
                        .collect(Collectors.toList());
            }
            LOGGER.info("{} Java files found for analysis.", filesToAnalyze.size());
        } else {
            // Ansonsten nur die einzelne Datei analysieren
            filesToAnalyze = Collections.singletonList(inputFile);
            LOGGER.info("1 Java file found for analysis.");
        }

        if (filesToAnalyze.isEmpty()) {
            LOGGER.info("No .java files found. The program will exit.");
            return;
        }

        // Führt den VirusTotal-Scan basierend auf dem Modus aus
        boolean proceedWithAnalysis = runVirusTotalScan(filesToAnalyze, inputFile, vtMode);

        if (!proceedWithAnalysis) {
            LOGGER.error("VirusTotal scan indicated potential malware or an error occurred. Aborting static analysis.");
            return;
        }
        // Ende der VT-Scan-Logik


        LOGGER.info("Continuing with static source code analysis.");
        List<Double> totalEntropies = new ArrayList<>();

        // Jede gefundene Datei einzeln analysieren
        for (File file : filesToAnalyze) {
            totalEntropies.addAll(analyzeFile(file));
        }

        LOGGER.info("Full analysis completed.");

        // Am Ende eine Gesamt-Entropie-Statistik ausgeben
        if (!totalEntropies.isEmpty()) {
            double sum = 0.0;
            for (double entropy : totalEntropies) {
                sum += entropy;
            }
            double averageEntropy = sum / totalEntropies.size();

            LOGGER.info("Total Average Identifier Entropy for Scan: {} (based on {} identifiers across {} files)",
                         df.format(averageEntropy), totalEntropies.size(), filesToAnalyze.size());

            // Warnen wenn der Durchschnittswert den Schwellenwert überschreitet
            if (averageEntropy > ENTROPY_OBUFSCATION_THRESHOLD) {
                LOGGER.warn("[HIGH] High average identifier entropy detected ({}). Project may be obfuscated.",
                            df.format(averageEntropy));
            }
        }
    }

    /**
     * Führt die VirusTotal-Scans basierend auf dem Modus aus
     * @param filesToAnalyze Liste der zu prüfenden Dateien
     * @param inputFile Das ursprüngliche Eingabe-Verzeichnis (für relative Pfade)
     * @param mode Der zu verwendende VtMode (OFF HASH_ONLY ZIP_ONLY DEFAULT)
     * @return true wenn die Analyse fortgesetzt werden soll (keine Malware gefunden)
     */
    private static boolean runVirusTotalScan(List<File> filesToAnalyze, File inputFile, VtMode mode) {
        if (mode == VtMode.OFF) {
            LOGGER.info("VirusTotal scanning is disabled (vt-mode=off).");
            return true;
        }

        LOGGER.info("Starting VirusTotal pre-check (mode: {})...", mode);
        VirusTotalAnalyzer vtAnalyzer = new VirusTotalAnalyzer();

        if (!vtAnalyzer.isConfigured()) {
            LOGGER.warn("The API key for VirusTotal is not configured. Skipping VT check.");
            return true; // Fortfahren wenn VT nicht konfiguriert ist
        }

        boolean runHashCheck = (mode == VtMode.HASH_ONLY || mode == VtMode.DEFAULT);
        boolean runZipUpload = (mode == VtMode.ZIP_ONLY || mode == VtMode.DEFAULT);
        boolean hashCheckPassed = true; // Zunächst annehmen dass der Check besteht

        // 1. Hash-Prüfung durchführen (wenn zutreffend)
        if (runHashCheck) {
            LOGGER.info("Performing individual file hash checks...");
            boolean anyMalicious = false;
            for (File file : filesToAnalyze) {
                try {
                    // Prüft ob der Hash der Datei bei VT als bösartig bekannt ist
                    if (vtAnalyzer.checkFileHash(file.getAbsolutePath())) {
                        LOGGER.error("[ANALYSIS CANCELED] File {} known to VirusTotal as malicious based on hash.", file.getName());
                        anyMalicious = true;
                        hashCheckPassed = false; // Markiert die Hash-Prüfung als fehlgeschlagen
                        break; // Prüfung weiterer Dateien stoppen
                    }
                } catch (IOException e) {
                    LOGGER.error("Error during VirusTotal hash check for {}. Proceeding cautiously.", file.getName(), e);
                    // Bei einem Fehler fahren wir fort aber markieren den Check als fehlgeschlagen
                    hashCheckPassed = false;
                }
            }
            if (anyMalicious) {
                return false; // Analyse stoppen wenn eine Datei bösartig ist
            }
            if (hashCheckPassed) {
                 LOGGER.info("Individual file hash checks completed. No known malicious files found.");
            } else {
                 LOGGER.warn("Individual file hash checks encountered errors or inconclusive results.");
            }
            // Wenn der Modus HASH_ONLY ist sind wir hier fertig mit VT
            if (mode == VtMode.HASH_ONLY) {
                return true; // Mit statischer Analyse fortfahren
            }
        }

        // 2. ZIP-Upload durchführen (falls zutreffend)
        // Im DEFAULT-Modus nur ausführen wenn die Hash-Prüfung erfolgreich war
        if (runZipUpload && (mode == VtMode.ZIP_ONLY || (mode == VtMode.DEFAULT && hashCheckPassed))) {
            LOGGER.info("Performing ZIP archive upload and analysis...");
            Path tempZipFile = null;
            try {
                tempZipFile = Files.createTempFile("analysis_bundle_", ".zip");
                LOGGER.debug("Creating temporary ZIP archive: {}", tempZipFile.toAbsolutePath()); // Temp-Pfad nur im Debug loggen

                // Basis-Pfad für relative Pfade im ZIP bestimmen
                Path inputBasePath = inputFile.isDirectory() ? inputFile.toPath() : inputFile.getParentFile().toPath();

                // Ein temporäres ZIP-Archiv mit allen Dateien erstellen
                try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(tempZipFile))) {
                    for (File file : filesToAnalyze) {
                        String relativePath = inputBasePath.relativize(file.toPath()).toString().replace('\\', '/');
                        ZipEntry zipEntry = new ZipEntry(relativePath);
                        zos.putNextEntry(zipEntry);
                        try (FileInputStream fis = new FileInputStream(file)) {
                            fis.transferTo(zos);
                        }
                        zos.closeEntry();
                    }
                }
                LOGGER.info("ZIP archive created for {} files.", filesToAnalyze.size());

                // Das ZIP bei VT hochladen und analysieren lassen
                String analysisId = vtAnalyzer.uploadFile(tempZipFile.toAbsolutePath().toString());
                boolean isMalicious = vtAnalyzer.getAnalysisReport(analysisId);

                if (isMalicious) {
                    LOGGER.error("[ANALYSIS CANCELED] Uploaded ZIP archive was classified as malicious by VirusTotal.");
                    return false;
                }
                LOGGER.info("VirusTotal ZIP scan completed. The archive appears to be clean.");
                return true; // Fortfahren mit Analyse

            } catch (Exception e) {
                LOGGER.error("Error during VirusTotal ZIP upload/analysis. Aborting analysis.", e);
                return false; // Analyse bei Fehler stoppen
            } finally {
                // Das temporäre ZIP-Archiv aufräumen
                if (tempZipFile != null) {
                    try {
                        Files.delete(tempZipFile);
                        LOGGER.debug("Temporary ZIP archive deleted.");
                    } catch (IOException e) {
                        LOGGER.warn("Could not delete the temporary ZIP file: {}", tempZipFile.toAbsolutePath());
                    }
                }
            }
        } else if (mode == VtMode.DEFAULT && !hashCheckPassed) {
             // Im DEFAULT-Modus den ZIP-Upload überspringen wenn Hashes fehlschlugen
             LOGGER.warn("Skipping ZIP upload due to issues during hash check phase.");
             return true; // Trotzdem mit statischer Analyse fortfahren
        }


        // Sollte nur erreicht werden wenn HASH_ONLY (bereits returned) oder DEFAULT
        // bei dem der Hash-Check bestanden wurde aber der ZIP-Upload nicht zutraf
        return true;
    }


    /**
     * Analysiert eine einzelne Java-Datei
     * Parst die Datei zu einem AST und startet den ForbiddenApiVisitor
     * @param sourceFile Die zu analysierende Quellcode-Datei
     * @return Eine Liste der gefundenen Entropie-Werte
     */
    private static List<Double> analyzeFile(File sourceFile) {
        String baseName = sourceFile.toPath().getFileName().toString();
        String scanTargetName = baseName.replaceFirst("[.][^.]+$", "");

        // Setzt den "scanTarget" für das file-spezifische Logging
        // Wird vom RoutingAppender in log4j2.xml verwendet
        ThreadContext.put("scanTarget", scanTargetName);

        LOGGER.info("Analyzing: {}", sourceFile.getAbsolutePath());
        List<Double> fileEntropies = new ArrayList<>();

        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        try (StandardJavaFileManager fileManager = compiler.getStandardFileManager(null, null, null)) {
            Iterable<? extends JavaFileObject> compilationUnits = fileManager.getJavaFileObjects(sourceFile);
            // "-proc:none" deaktiviert die Annotation-Verarbeitung
            List<String> options = List.of("-proc:none");
            JavaCompiler.CompilationTask task = compiler.getTask(null, fileManager, null, options, null, compilationUnits);

            // Den AST (Abstract Syntax Tree) parsen
            JavacTask javacTask = (JavacTask) task;
            SourcePositions sourcePositions = Trees.instance(javacTask).getSourcePositions();
            Iterable<? extends CompilationUnitTree> asts = javacTask.parse();

            for (CompilationUnitTree ast : asts) {
                // Den Visitor für diesen AST erstellen und starten
                ForbiddenApiVisitor visitor = new ForbiddenApiVisitor(ast, sourcePositions);
                visitor.scan(ast, null); // Startet den Scan

                // Violations sammeln und loggen
                List<Violation> violations = visitor.getViolations();
                if (violations.isEmpty()) {
                    LOGGER.info("No rule violations found in {}.", sourceFile.getName());
                } else {
                    for (Violation violation : violations) {
                        LOGGER.warn(violation.toString());
                    }
                }

                // Entropie-Werte sammeln
                fileEntropies.addAll(visitor.getIdentifierEntropies());
            }
        } catch (Exception e) {
            LOGGER.error("File could not be analyzed: {}", sourceFile.getAbsolutePath(), e);
        } finally {
            // Wichtig: Nur den "scanTarget" entfernen
            // "logFile" muss für den globalen Logger erhalten bleiben
            ThreadContext.remove("scanTarget");
        }
        return fileEntropies;
    }
}
