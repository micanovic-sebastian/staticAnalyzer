package org.example.analyzer;

import java.lang.reflect.Method;
import java.net.URL;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

public class SandboxRunner {

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java -cp stat.jar org.example.analyzer.SandboxRunner <path-to-target-jar> [args...]");
            return;
        }

        String targetJarPath = args[0];
        try {
            // 1. Get the Main-Class from the target JAR's manifest
            JarFile jarFile = new JarFile(targetJarPath);
            Manifest manifest = jarFile.getManifest();
            String mainClassName = manifest.getMainAttributes().getValue("Main-Class");
            jarFile.close();

            if (mainClassName == null) {
                System.err.println("Error: No 'Main-Class' attribute found in " + targetJarPath);
                return;
            }

            // 2. Create the URL for the target JAR
            URL[] urls = { new URL("file:" + targetJarPath) };

            // 3. Create our SecureClassLoader directly.
            // We pass null to use the default system classloader as the ultimate parent.
            SecureClassLoader secureLoader = new SecureClassLoader(urls, ClassLoader.getSystemClassLoader().getParent());

            // 4. Load the main class using our secure loader
            System.out.println("Sandbox: Loading main class '" + mainClassName + "'...");
            Class<?> mainClass = secureLoader.loadClass(mainClassName);

            // 5. Find the main method
            Method mainMethod = mainClass.getMethod("main", String[].class);

            // 6. Prepare arguments for the target application
            String[] targetArgs = new String[args.length - 1];
            System.arraycopy(args, 1, targetArgs, 0, targetArgs.length);

            // 7. Run the application inside the sandbox
            System.out.println("Sandbox: Starting application...");
            System.out.println("----------------------------------------");
            mainMethod.invoke(null, (Object) targetArgs);
            System.out.println("----------------------------------------");
            System.out.println("Sandbox: Application finished.");

        } catch (Exception e) {
            System.err.println("\nSandbox: An error occurred while running the application.");
            e.printStackTrace();
        }
    }
}