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
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class StaticAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(StaticAnalyzer.class);

    // Globale Counter für die durchschnittliche Code-Komplexität.
    private static int totalMethodCount = 0;
    private static int totalComplexitySum = 0;
    private static final DecimalFormat df = new DecimalFormat("0.00");

    public static void main(String[] args) throws IOException {
        if (args.length == 0) {
            LOGGER.error("Benutzung: java StaticAnalyzer <Pfad> [vt-mode]");
            return;
        }

        // Hier die Command line args verarbeiten.
        List<String> argList = new ArrayList<>(Arrays.asList(args));

        // Checken ob der VirusTotal Modus an ist.
        boolean isVtModeEnabled = argList.remove("vt-mode");

        if (argList.isEmpty()) {
            LOGGER.error("Kein Pfad angegeben. Benutzung: java StaticAnalyzer <Pfad> [vt-mode]");
            return;
        }

        // Das erste Argument was noch da ist sollte der Pfad sein.
        String inputPath = argList.get(0);

        File inputFile = new File(inputPath);
        if (!inputFile.exists()) {
            LOGGER.error("Der Pfad existiert nicht: {}", inputPath);
            return;
        }

        List<File> filesToAnalyze;
        if (inputFile.isDirectory()) {
            // Wenn es ein Ordner ist alle .java files da drin sammeln.
            LOGGER.info("Durchsuche Verzeichnis: {}", inputPath);
            try (Stream<Path> walk = Files.walk(inputFile.toPath())) {
                filesToAnalyze = walk
                        .filter(Files::isRegularFile)
                        .filter(p -> p.toString().endsWith(".java"))
                        .map(Path::toFile)
                        .collect(Collectors.toList());
            }
            LOGGER.info("Es wurden {} Java-Dateien zur Analyse gefunden.", filesToAnalyze.size());
        } else {
            // Wenns nur eine Datei ist dann nur das analysieren.
            filesToAnalyze = Collections.singletonList(inputFile);
            LOGGER.info("Es wurde 1 Java-Datei zur Analyse gefunden.");
        }

        if (filesToAnalyze.isEmpty()) {
            LOGGER.info("Keine .java-Dateien gefunden. Das Programm wird beendet.");
            return;
        }

        // Wenn vt-mode an ist machen wir erst einen Virus-Scan.
        if (isVtModeEnabled) {
            LOGGER.info("Starte Vorab-Prüfung mit VirusTotal (vt-mode aktiviert)...");
            VirusTotalAnalyzer vtAnalyzer = new VirusTotalAnalyzer();

            if (!vtAnalyzer.isConfigured()) {
                LOGGER.warn("Der API-Schlüssel für VirusTotal ist nicht konfiguriert. Die Prüfung wird übersprungen.");
            } else {
                Path tempZipFile = null;
                try {
                    // Alle Dateien kommen in ein temp zip file.
                    tempZipFile = Files.createTempFile("analysis_bundle_", ".zip");
                    LOGGER.info("Erstelle ein ZIP-Archiv für {} Dateien...", filesToAnalyze.size());

                    Path inputBasePath = inputFile.isDirectory() ? inputFile.toPath() : inputFile.getParentFile().toPath();

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
                    LOGGER.info("ZIP-Archiv erstellt: {}", tempZipFile.toAbsolutePath());

                    // Das Zip-File zu VirusTotal hochladen und analysieren lassen
                    String analysisId = vtAnalyzer.uploadFile(tempZipFile.toAbsolutePath().toString());
                    boolean isMalicious = vtAnalyzer.getAnalysisReport(analysisId);

                    if (isMalicious) {
                        LOGGER.error("[ANALYSE ABGEBROCHEN] Das ZIP-Archiv wurde von VirusTotal als schädlich eingestuft.");
                        return;
                    }
                    LOGGER.info("VirusTotal-Prüfung abgeschlossen. Das Archiv scheint sauber zu sein.");

                } catch (Exception e) {
                    LOGGER.error("Fehler bei der VirusTotal-Analyse. Die statische Analyse wird abgebrochen.", e);
                    return;
                } finally {
                    // die Temp-Zip-Datei danach wieder löschen.
                    if (tempZipFile != null) {
                        try {
                            Files.delete(tempZipFile);
                            LOGGER.info("Temporäres ZIP-Archiv wurde gelöscht.");
                        } catch (IOException e) {
                            LOGGER.warn("Konnte die temporäre ZIP-Datei nicht löschen: {}", tempZipFile.toAbsolutePath());
                        }
                    }
                }
            }
        } else {
            LOGGER.info("Überspringe die VirusTotal-Prüfung (vt-mode nicht angegeben).");
        }

        LOGGER.info("Fahre mit der statischen Quellcode-Analyse fort.");
        // Counter für die Komplexität vor dem Scan auf Null setzen
        totalMethodCount = 0;
        totalComplexitySum = 0;

        for (File file : filesToAnalyze) {
            analyzeFile(file);
        }


        // Am ende die durchschnittliche Komplexität von allen Methoden ausgeben.
        if (totalMethodCount > 0) {
            double averageComplexity = (double) totalComplexitySum / totalMethodCount;
            LOGGER.info("----------------------------------------");
            LOGGER.info("Vollständige Analyse abgeschlossen.");
            LOGGER.info("Insgesamt analysierte Methoden: {}", totalMethodCount);
            LOGGER.info("Zyklomatische Gesamtkomplexität: {}", totalComplexitySum);
            LOGGER.info("Durchschnittliche zyklomatische Komplexität: {}", df.format(averageComplexity));
        } else {
            LOGGER.info("Vollständige Analyse abgeschlossen. Es wurden keine Methoden zur Analyse gefunden.");
        }
    }

    // Diese methode analysiert Java-Dateien
    private static void analyzeFile(File sourceFile) {
        // der Dateiname wird für die Log-Ausgabe vorbereitet.
        String baseName = sourceFile.toPath().getFileName().toString();
        String scanTargetName = baseName.replaceFirst("[.][^.]+$", "");
        ThreadContext.put("scanTarget", scanTargetName);

        LOGGER.info("Analysiere: {}", sourceFile.getAbsolutePath());

        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        try (StandardJavaFileManager fileManager = compiler.getStandardFileManager(null, null, null)) {
            Iterable<? extends JavaFileObject> compilationUnits = fileManager.getJavaFileObjects(sourceFile);

            // Compiler-Parameter damit Annotation Processing aus ist.
            List<String> options = List.of("-proc:none");
            JavaCompiler.CompilationTask task = compiler.getTask(null, fileManager, null, options, null, compilationUnits);

            // der Source Code wird zu einem AST geparsed.
            JavacTask javacTask = (JavacTask) task;
            SourcePositions sourcePositions = Trees.instance(javacTask).getSourcePositions();
            Iterable<? extends CompilationUnitTree> asts = javacTask.parse();

            for (CompilationUnitTree ast : asts) {
                // ein Visitor läuft durch den AST und prüft den Code gegen die Regeln.
                ForbiddenApiVisitor visitor = new ForbiddenApiVisitor(ast, sourcePositions);
                visitor.scan(ast, null);

                List<Violation> violations = visitor.getViolations();
                if (violations.isEmpty()) {
                    LOGGER.info("Keine Regelverstöße in {} gefunden.", sourceFile.getName());
                } else {
                    for (Violation violation : violations) {
                        LOGGER.warn(violation.toString());
                    }
                }

                // die Komplexität von jeder Methode wird geloggt.
                Map<String, Integer> complexities = visitor.getMethodComplexities();
                if (!complexities.isEmpty()) {
                    LOGGER.info("--- Zyklomatische Komplexität ---");
                    for (Map.Entry<String, Integer> entry : complexities.entrySet()) {
                        LOGGER.info("  - Methode: {} | Komplexität: {}", entry.getKey(), entry.getValue());
                        totalComplexitySum += entry.getValue();
                        totalMethodCount++;
                    }
                    LOGGER.info("-------------------------------");
                }
            }
        } catch (Exception e) {
            LOGGER.error("Datei konnte nicht analysiert werden: {}", sourceFile.getAbsolutePath(), e);
        } finally {
            // wichtig damit die Logs für die nächste Datei wieder leer sind.
            ThreadContext.clearAll();
        }
    }
}

