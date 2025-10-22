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

    public static void main(String[] args) throws IOException {
        if (args.length == 0) {
            LOGGER.error("Usage: java StaticAnalyzer <Path> [vt-mode]");
            return;
        }

        // Process the command line args here.
        List<String> argList = new ArrayList<>(Arrays.asList(args));

        // Check if VirusTotal mode is on.
        boolean isVtModeEnabled = argList.remove("vt-mode");

        if (argList.isEmpty()) {
            LOGGER.error("No path specified. Usage: java StaticAnalyzer <Path> [vt-mode]");
            return;
        }

        // The first remaining argument should be the path.
        String inputPath = argList.get(0);

        File inputFile = new File(inputPath);
        if (!inputFile.exists()) {
            LOGGER.error("The path does not exist: {}", inputPath);
            return;
        }

        List<File> filesToAnalyze;
        if (inputFile.isDirectory()) {
            // If it's a directory, collect all .java files within it.
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
            // If it's just a single file, analyze only that.
            filesToAnalyze = Collections.singletonList(inputFile);
            LOGGER.info("1 Java file found for analysis.");
        }

        if (filesToAnalyze.isEmpty()) {
            LOGGER.info("No .java files found. The program will exit.");
            return;
        }

        // If vt-mode is on, perform a virus scan first.
        if (isVtModeEnabled) {
            LOGGER.info("Starting pre-check with VirusTotal (vt-mode enabled)...");
            VirusTotalAnalyzer vtAnalyzer = new VirusTotalAnalyzer();

            if (!vtAnalyzer.isConfigured()) {
                LOGGER.warn("The API key for VirusTotal is not configured. Skipping check.");
            } else {
                Path tempZipFile = null;
                try {
                    // Put all files into a temp zip file.
                    tempZipFile = Files.createTempFile("analysis_bundle_", ".zip");
                    LOGGER.info("Creating a ZIP archive for {} files...", filesToAnalyze.size());

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
                    LOGGER.info("ZIP archive created: {}", tempZipFile.toAbsolutePath());

                    // Upload the zip file to VirusTotal and let it be analyzed
                    String analysisId = vtAnalyzer.uploadFile(tempZipFile.toAbsolutePath().toString());
                    boolean isMalicious = vtAnalyzer.getAnalysisReport(analysisId);

                    if (isMalicious) {
                        LOGGER.error("[ANALYSIS CANCELED] The ZIP archive was classified as malicious by VirusTotal.");
                        return;
                    }
                    LOGGER.info("VirusTotal check completed. The archive appears to be clean.");

                } catch (Exception e) {
                    LOGGER.error("Error during VirusTotal analysis. Static analysis will be canceled.", e);
                    return;
                } finally {
                    // Delete the temp zip file afterward.
                    if (tempZipFile != null) {
                        try {
                            Files.delete(tempZipFile);
                            LOGGER.info("Temporary ZIP archive has been deleted.");
                        } catch (IOException e) {
                            LOGGER.warn("Could not delete the temporary ZIP file: {}", tempZipFile.toAbsolutePath());
                        }
                    }
                }
            }
        } else {
            LOGGER.info("Skipping VirusTotal check (vt-mode not specified).");
        }

        LOGGER.info("Continuing with static source code analysis.");

        for (File file : filesToAnalyze) {
            analyzeFile(file);
        }

        LOGGER.info("Full analysis completed.");
    }

    // This method analyzes Java files
    private static void analyzeFile(File sourceFile) {
        // The file name is prepared for log output.
        String baseName = sourceFile.toPath().getFileName().toString();
        String scanTargetName = baseName.replaceFirst("[.][^.]+$", "");
        ThreadContext.put("scanTarget", scanTargetName);

        LOGGER.info("Analyzing: {}", sourceFile.getAbsolutePath());

        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        try (StandardJavaFileManager fileManager = compiler.getStandardFileManager(null, null, null)) {
            Iterable<? extends JavaFileObject> compilationUnits = fileManager.getJavaFileObjects(sourceFile);

            // Compiler parameters to disable annotation processing.
            List<String> options = List.of("-proc:none");
            JavaCompiler.CompilationTask task = compiler.getTask(null, fileManager, null, options, null, compilationUnits);

            // The source code is parsed into an AST.
            JavacTask javacTask = (JavacTask) task;
            SourcePositions sourcePositions = Trees.instance(javacTask).getSourcePositions();
            Iterable<? extends CompilationUnitTree> asts = javacTask.parse();

            for (CompilationUnitTree ast : asts) {
                // A visitor walks through the AST and checks the code against the rules.
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
            }
        } catch (Exception e) {
            LOGGER.error("File could not be analyzed: {}", sourceFile.getAbsolutePath(), e);
        } finally {
            // Important so that the logs are clear for the next file.
            ThreadContext.clearAll();
        }
    }
}