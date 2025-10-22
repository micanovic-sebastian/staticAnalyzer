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
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class StaticAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(StaticAnalyzer.class);

    private static final double ENTROPY_OBUFSCATION_THRESHOLD = 4;
    private static final DecimalFormat df = new DecimalFormat("0.00");

    // --- NEW: Enum for VirusTotal Modes ---
    private enum VtMode {
        OFF,        // No VT scan
        HASH_ONLY,  // Only check individual file hashes
        ZIP_ONLY,   // Only upload ZIP archive
        DEFAULT     // Check hashes first, then upload ZIP if unknown/clean
    }

    public static void main(String[] args) throws IOException {
        if (args.length == 0) {
            LOGGER.error("Usage: java StaticAnalyzer <Path> [vt-mode=off|hash|zip]");
            return;
        }

        // --- MODIFIED: Argument Parsing ---
        String inputPath = null;
        VtMode vtMode = VtMode.DEFAULT; // Default VT behavior

        for (String arg : args) {
            if (arg.startsWith("vt-mode=")) {
                String modeStr = arg.substring("vt-mode=".length()).toLowerCase();
                switch (modeStr) {
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
                        LOGGER.error("Invalid vt-mode specified: {}. Valid options are off, hash, zip.", modeStr);
                        return;
                }
            } else if (inputPath == null) {
                inputPath = arg;
            } else {
                LOGGER.error("Too many arguments. Usage: java StaticAnalyzer <Path> [vt-mode=off|hash|zip]");
                return;
            }
        }

        if (inputPath == null) {
            LOGGER.error("No path specified. Usage: java StaticAnalyzer <Path> [vt-mode=off|hash|zip]");
            return;
        }
        // --- End of Argument Parsing ---


        File inputFile = new File(inputPath);
        if (!inputFile.exists()) {
            LOGGER.error("The path does not exist: {}", inputPath);
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
            LOGGER.info("{} Java files found for analysis.", filesToAnalyze.size());
        } else {
            filesToAnalyze = Collections.singletonList(inputFile);
            LOGGER.info("1 Java file found for analysis.");
        }

        if (filesToAnalyze.isEmpty()) {
            LOGGER.info("No .java files found. The program will exit.");
            return;
        }

        // --- MODIFIED: Run VirusTotal Scan based on mode ---
        boolean proceedWithAnalysis = runVirusTotalScan(filesToAnalyze, inputFile, vtMode);

        if (!proceedWithAnalysis) {
            LOGGER.error("VirusTotal scan indicated potential malware or an error occurred. Aborting static analysis.");
            return;
        }
        // --- End of VT Scan Logic ---


        LOGGER.info("Continuing with static source code analysis.");
        List<Double> totalEntropies = new ArrayList<>();

        for (File file : filesToAnalyze) {
            totalEntropies.addAll(analyzeFile(file));
        }

        LOGGER.info("Full analysis completed.");

        if (!totalEntropies.isEmpty()) {
            double sum = 0.0;
            for (double entropy : totalEntropies) {
                sum += entropy;
            }
            double averageEntropy = sum / totalEntropies.size();

            LOGGER.info("--------------------------------------------------");
            LOGGER.info("Total Average Identifier Entropy for Scan: {} (based on {} identifiers across {} files)",
                         df.format(averageEntropy), totalEntropies.size(), filesToAnalyze.size());

            if (averageEntropy > ENTROPY_OBUFSCATION_THRESHOLD) {
                LOGGER.warn("[HIGH] High average identifier entropy detected ({}). Project may be obfuscated.",
                            df.format(averageEntropy));
            }
             LOGGER.info("--------------------------------------------------");
        }
    }

    // --- NEW: Method to handle VirusTotal Scanning ---
    /**
     * Runs VirusTotal scans based on the specified mode.
     * @param filesToAnalyze List of files to check.
     * @param inputFile Original input file/directory (used for path relativization).
     * @param mode The VtMode to use (OFF, HASH_ONLY, ZIP_ONLY, DEFAULT).
     * @return true if the analysis should proceed (no malware detected), false otherwise.
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
            return true; // Proceed if VT is not configured
        }

        boolean runHashCheck = (mode == VtMode.HASH_ONLY || mode == VtMode.DEFAULT);
        boolean runZipUpload = (mode == VtMode.ZIP_ONLY || mode == VtMode.DEFAULT);
        boolean hashCheckPassed = true; // Assume pass initially

        // 1. Perform Hash Check (if applicable)
        if (runHashCheck) {
            LOGGER.info("Performing individual file hash checks...");
            boolean anyMalicious = false;
            for (File file : filesToAnalyze) {
                try {
                    if (vtAnalyzer.checkFileHash(file.getAbsolutePath())) {
                        LOGGER.error("[ANALYSIS CANCELED] File {} known to VirusTotal as malicious based on hash.", file.getName());
                        anyMalicious = true;
                        hashCheckPassed = false; // Mark hash check as failed
                        break; // Stop checking other files
                    }
                } catch (IOException e) {
                    LOGGER.error("Error during VirusTotal hash check for {}. Proceeding cautiously.", file.getName(), e);
                    // Decide if you want to abort on error or continue. Let's continue but skip zip upload if default.
                    hashCheckPassed = false; // Mark hash check as failed due to error
                }
            }
            if (anyMalicious) {
                return false; // Stop analysis if any file is known malicious
            }
            if (hashCheckPassed) {
                 LOGGER.info("Individual file hash checks completed. No known malicious files found.");
            } else {
                 LOGGER.warn("Individual file hash checks encountered errors or inconclusive results.");
            }
            // If mode is HASH_ONLY, we are done with VT checks.
            if (mode == VtMode.HASH_ONLY) {
                return true; // Proceed with static analysis as no known malicious hashes were found
            }
        }

        // 2. Perform Zip Upload (if applicable and hash check didn't fail in DEFAULT mode)
        // Skip zip upload in DEFAULT mode if hash check encountered errors/inconclusive results
        if (runZipUpload && (mode == VtMode.ZIP_ONLY || (mode == VtMode.DEFAULT && hashCheckPassed))) {
            LOGGER.info("Performing ZIP archive upload and analysis...");
            Path tempZipFile = null;
            try {
                tempZipFile = Files.createTempFile("analysis_bundle_", ".zip");
                LOGGER.debug("Creating temporary ZIP archive: {}", tempZipFile.toAbsolutePath()); // Use debug for temp file path

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
                LOGGER.info("ZIP archive created for {} files.", filesToAnalyze.size());

                String analysisId = vtAnalyzer.uploadFile(tempZipFile.toAbsolutePath().toString());
                boolean isMalicious = vtAnalyzer.getAnalysisReport(analysisId);

                if (isMalicious) {
                    LOGGER.error("[ANALYSIS CANCELED] Uploaded ZIP archive was classified as malicious by VirusTotal.");
                    return false;
                }
                LOGGER.info("VirusTotal ZIP scan completed. The archive appears to be clean.");
                return true; // Proceed with analysis

            } catch (Exception e) {
                LOGGER.error("Error during VirusTotal ZIP upload/analysis. Aborting analysis.", e);
                return false; // Stop analysis on error
            } finally {
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
             LOGGER.warn("Skipping ZIP upload due to issues during hash check phase.");
             return true; // Proceed with static analysis despite hash check issues
        }


        // Should only reach here if mode was HASH_ONLY (already returned) or DEFAULT where hash passed
        // but zip upload wasn't applicable (e.g. error during hash check prevented it).
        return true;
    }


    private static List<Double> analyzeFile(File sourceFile) {
        String baseName = sourceFile.toPath().getFileName().toString();
        String scanTargetName = baseName.replaceFirst("[.][^.]+$", "");
        ThreadContext.put("scanTarget", scanTargetName);

        LOGGER.info("Analyzing: {}", sourceFile.getAbsolutePath());
        List<Double> fileEntropies = new ArrayList<>();

        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        try (StandardJavaFileManager fileManager = compiler.getStandardFileManager(null, null, null)) {
            Iterable<? extends JavaFileObject> compilationUnits = fileManager.getJavaFileObjects(sourceFile);
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
                    LOGGER.info("No rule violations found in {}.", sourceFile.getName());
                } else {
                    for (Violation violation : violations) {
                        LOGGER.warn(violation.toString());
                    }
                }

                fileEntropies.addAll(visitor.getIdentifierEntropies());
            }
        } catch (Exception e) {
            LOGGER.error("File could not be analyzed: {}", sourceFile.getAbsolutePath(), e);
        } finally {
            ThreadContext.clearAll();
        }
        return fileEntropies;
    }
}