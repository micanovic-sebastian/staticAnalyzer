package org.example.test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;

public class SensitiveFileAccess {

    // This method should be flagged by your FileOperationAnalyzer.
    public void readSystemFile() {
        // A common target for information stealers on Linux.
        File shadowFile = new File("/etc/shadow");
        if (shadowFile.exists()) {
            System.out.println("Attempting to access /etc/shadow");
        }
    }

    // This method should also be flagged as it targets a sensitive user directory.
    public void writeToUserDirectory() {
        String userHome = System.getProperty("user.home");
        try {
            // Malware often writes to startup or configuration files.
            Files.write(Paths.get(userHome, ".suspicious_config"), Collections.singleton("payload"));
        } catch (IOException e) {
            // Ignored for this example.
        }
    }

    // This method accesses a non-sensitive path and should NOT be flagged.
    public void writeToLocalDirectory() throws IOException {
        Files.write(Paths.get("safe_file.txt"), Collections.singleton("This is safe."));
    }
}