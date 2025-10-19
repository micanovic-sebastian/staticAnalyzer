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
import java.text.DecimalFormat; // <-- ADDED
import java.util.Collections;
import java.util.List;
import java.util.Map; // <-- ADDED
import java.util.stream.Collectors;
import java.util.stream.Stream;
// Import for Zipping
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class StaticAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(StaticAnalyzer.class);

    // --- NEW: Globals for complexity average ---
    private static int totalMethodCount = 0;
    private static int totalComplexitySum = 0;
    private static final DecimalFormat df = new DecimalFormat("0.00");
    // --- END NEW ---

    public static void main(String[] args) throws IOException {
        if (args.length == 0) {
            LOGGER.error("Usage: java StaticAnalyzer <path-to-java-file-or-directory>");
            return;
        }

        String inputPath = args[0];
        File inputFile = new File(inputPath);
        if (!inputFile.exists()) {
            LOGGER.error("Path does not exist: {}", inputPath);
            return;
        }

        List<File> filesToAnalyze;
        if (inputFile.isDirectory()) {
            LOGGER.info("Scanning directory: {}", inputPath);
            try (Stream<Path> walk = Files.walk(inputFile.toPath())) {
                filesToAnalyze = walk
                        .filter(Files::isRegularFile)
                        .filter(p -> p.toString().endsWith(".java"))
                        .map(Path::toFile)
                        .collect(Collectors.toList());
            }
            LOGGER.info("Found {} java files to analyze.", filesToAnalyze.size());
        } else {
            // If it's a single file, just analyze that one
            filesToAnalyze = Collections.singletonList(inputFile);
            LOGGER.info("Found 1 java file to analyze.");
        }

        if (filesToAnalyze.isEmpty()) {
            LOGGER.info("No .java files found. Exiting.");
            return;
        }

        // --- NEW: VirusTotal Pre-Check (Zipped) ---
        LOGGER.info("Starting VirusTotal pre-check...");
        VirusTotalAnalyzer vtAnalyzer = new VirusTotalAnalyzer();

        if (!vtAnalyzer.isConfigured()) {
            LOGGER.warn("VT_API_KEY not set. Skipping VirusTotal pre-check.");
        } else {
            Path tempZipFile = null;
            try {
                // 1. Create a temporary zip file
                tempZipFile = Files.createTempFile("analysis_bundle_", ".zip");
                LOGGER.info("Creating zip bundle for {} files...", filesToAnalyze.size());

                // Determine base path for relative file names in zip
                Path inputBasePath = inputFile.isDirectory() ? inputFile.toPath() : inputFile.getParentFile().toPath();

                // 2. Add all files to the zip
                try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(tempZipFile))) {
                    for (File file : filesToAnalyze) {
                        // Create relative paths for files in zip
                        String relativePath = inputBasePath.relativize(file.toPath()).toString().replace('\\', '/');
                        ZipEntry zipEntry = new ZipEntry(relativePath);
                        zos.putNextEntry(zipEntry);

                        try (FileInputStream fis = new FileInputStream(file)) {
                            fis.transferTo(zos);
                        }
                        zos.closeEntry();
                    }
                }
                LOGGER.info("Zip bundle created: {}", tempZipFile.toAbsolutePath());

                // 3. Upload and check the single zip file
                String analysisId = vtAnalyzer.uploadFile(tempZipFile.toAbsolutePath().toString());
                boolean isMalicious = vtAnalyzer.getAnalysisReport(analysisId);

                if (isMalicious) {
                    LOGGER.error("[ANALYSIS ABORTED] Zip bundle was flagged as malicious by VirusTotal.");
                    return; // Abort the entire operation
                }
                LOGGER.info("VirusTotal pre-check complete. Bundle appears clean.");

            } catch (Exception e) {
                LOGGER.error("Error during VirusTotal analysis. Aborting static analysis.", e);
                return;
            } finally {
                // 4. Clean up the temporary zip file
                if (tempZipFile != null) {
                    try {
                        Files.delete(tempZipFile);
                        LOGGER.info("Deleted temporary zip bundle.");
                    } catch (IOException e) {
                        LOGGER.warn("Could not delete temporary zip file: {}", tempZipFile.toAbsolutePath());
                    }
                }
            }
        }
        // --- End of VirusTotal Pre-Check ---

        LOGGER.info("Proceeding with static source code analysis.");
        // --- NEW: Reset counters before scan ---
        totalMethodCount = 0;
        totalComplexitySum = 0;
        // --- END NEW ---

        for (File file : filesToAnalyze) {
            analyzeFile(file);
        }

        // --- NEW: Report final average complexity ---
        if (totalMethodCount > 0) {
            double averageComplexity = (double) totalComplexitySum / totalMethodCount;
            LOGGER.info("----------------------------------------");
            LOGGER.info("Full analysis complete.");
            LOGGER.info("Total Methods Analyzed: {}", totalMethodCount);
            LOGGER.info("Total Cyclomatic Complexity: {}", totalComplexitySum);
            LOGGER.info("Average Cyclomatic Complexity: {}", df.format(averageComplexity));
        } else {
            LOGGER.info("Full analysis complete. No methods were found to analyze.");
        }
        // --- END NEW ---
    }

    private static void analyzeFile(File sourceFile) {
        String baseName = sourceFile.toPath().getFileName().toString();
        String scanTargetName = baseName.replaceFirst("[.][^.]+$", "");
        ThreadContext.put("scanTarget", scanTargetName);

        LOGGER.info("----------------------------------------");
        LOGGER.info("Analyzing: {}", sourceFile.getAbsolutePath());

        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        try (StandardJavaFileManager fileManager = compiler.getStandardFileManager(null, null, null)) {
            Iterable<? extends JavaFileObject> compilationUnits = fileManager.getJavaFileObjects(sourceFile);

            // Add compiler options to disable annotation processing
            List<String> options = List.of("-proc:none");
            JavaCompiler.CompilationTask task = compiler.getTask(null, fileManager, null, options, null, compilationUnits);

            JavacTask javacTask = (JavacTask) task;
            SourcePositions sourcePositions = Trees.instance(javacTask).getSourcePositions();
            Iterable<? extends CompilationUnitTree> asts = javacTask.parse();

            for (CompilationUnitTree ast : asts) {
                ForbiddenApiVisitor visitor = new ForbiddenApiVisitor(ast, sourcePositions);
                visitor.scan(ast, null);

                List<Violation> violations = visitor.getViolations();
                if (violations.isEmpty()) {
                    LOGGER.info("No violations found in {}.", baseName);
                } else {
                    for (Violation violation : violations) {
                        LOGGER.warn(violation.toString());
                    }
                }

                // --- NEW: Process and log Cyclomatic Complexity ---
                Map<String, Integer> complexities = visitor.getMethodComplexities();
                if (!complexities.isEmpty()) {
                    LOGGER.info("--- Cyclomatic Complexity ---");
                    for (Map.Entry<String, Integer> entry : complexities.entrySet()) {
                        LOGGER.info("  - Method: {} | Complexity: {}", entry.getKey(), entry.getValue());
                        totalComplexitySum += entry.getValue();
                        totalMethodCount++;
                    }
                    LOGGER.info("-------------------------------");
                }
                // --- END NEW ---
            }
        } catch (Exception e) {
            LOGGER.error("Could not analyze file: {}", sourceFile.getAbsolutePath(), e);
        } finally {
            ThreadContext.clearAll();
        }
    }
}