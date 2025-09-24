package org.example.analyzer;

import java.util.Set;
import java.util.regex.Pattern;

public class DenyList {

    public static final Set<String> FORBIDDEN_PACKAGES = Set.of(
        "java.lang.reflect",        // For dynamic code execution and evasion.
        "com.sun.jna",              // For calling native OS functions directly.
        "java.lang.instrument",     // For modifying bytecode of running applications.
        "com.sun.tools.attach"      // For attaching to and manipulating other JVMs.
    );

    public static final Set<String> FORBIDDEN_CLASSES = Set.of(
        // Process Execution & System Manipulation
        "java.lang.Runtime",
        "java.lang.ProcessBuilder",
        "sun.misc.Unsafe",          // For direct memory manipulation.

        // Desktop Espionage
        "java.awt.Robot",           // For screen capture and simulating user input.

        // Dynamic Code Loading
        "java.net.URLClassLoader"   // For loading code from remote URLs.
    );

    public static final Set<String> FORBIDDEN_METHODS = Set.of(
        "java.lang.Runtime.exec",
        "java.lang.System.exit",

        // Native Code Loading
        "java.lang.System.load",
        "java.lang.System.loadLibrary"
    );

    public static final Set<String> SUSPICIOUS_CLASSES = Set.of(
        // Cryptomining Indicators
        "java.math.BigInteger",
        "java.security.MessageDigest",
        "java.util.concurrent.ExecutorService",
        "java.util.concurrent.ThreadPoolExecutor",

        // Dangerous Deserialization
        "java.io.ObjectInputStream", // Can lead to RCE if stream is untrusted.

        // General File Access (to be checked by the path analyzer)
        "java.io.File"
    );

    public static final Set<String> SUSPICIOUS_FILE_PATHS = Set.of(
        // Windows file paths
        "c:/windows",
        "c:\\windows",
        "system32",
        "program files",
        "appdata",
        // Linux file paths
        "/etc/",
        "/bin/",
        "/sbin/",
        "/usr/bin/",
        "/usr/sbin/",
        "/var/log/",
        // User home directory - often a target for ransomware or info stealers
        "user.home" // We will check for System.getProperty("user.home")
    );

        /**
     * Methods that introduce untrusted, external data into the program.
     * The return values of these methods are considered "tainted".
     */
    public static final Set<String> TAINT_SOURCES = Set.of(
        "java.net.Socket.getInputStream",
        "java.nio.channels.SocketChannel.read",
        "java.io.FileInputStream.read"
        // In a real-world tool, you would add many more sources,
        // such as methods that read HTTP request parameters.
    );

    /**
     * Methods that are dangerous if called with tainted data.
     * These are the "sinks" we want to protect.
     */
    public static final Set<String> SENSITIVE_SINKS = Set.of(
        "java.lang.Runtime.exec",
        "java.lang.ProcessBuilder.start",
        "java.io.File.new", // Using tainted data for a file path is dangerous
        "java.nio.file.Paths.get"
    );

    public static final Set<String> OBFUSCATION_METHODS = Set.of(
        "java.util.Base64.getDecoder" // The starting point for Base64 decoding.
    );

        /**
     * Regex patterns for detecting suspicious string literals.
     */
    public static final Pattern IP_ADDRESS_PATTERN =
        Pattern.compile("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b");

    /**
     * Integer literals that are suspicious, often used for C2 connections.
     */
    public static final Set<Integer> SUSPICIOUS_PORTS = Set.of(
        1337, // Common "leet" port
        4444, // Default Metasploit port
        6667, // Common IRC port used for botnets
        31337 // Back Orifice port
    );
}