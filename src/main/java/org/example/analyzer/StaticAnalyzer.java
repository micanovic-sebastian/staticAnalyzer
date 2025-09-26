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
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class StaticAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(StaticAnalyzer.class);

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
            filesToAnalyze = Collections.singletonList(inputFile);
        }

        for (File file : filesToAnalyze) {
            analyzeFile(file);
        }

        LOGGER.info("Full analysis complete.");
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
            JavaCompiler.CompilationTask task = compiler.getTask(null, fileManager, null, null, null, compilationUnits);

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
            }
        } catch (Exception e) {
            LOGGER.error("Could not analyze file: {}", sourceFile.getAbsolutePath(), e);
        } finally {
            ThreadContext.clearAll();
        }
    }
}