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
        "java.lang.Runtime",
        "java.lang.ProcessBuilder",
        "sun.misc.Unsafe",

        "java.awt.Robot",

        "java.net.URLClassLoader"
    );

    public static final Set<String> FORBIDDEN_METHODS = Set.of(
        "java.lang.Runtime.exec",
        "java.lang.System.exit",

        "java.lang.System.load",
        "java.lang.System.loadLibrary"
    );

    public static final Set<String> SUSPICIOUS_CLASSES = Set.of(
        "java.math.BigInteger",
        "java.security.MessageDigest",
        "java.util.concurrent.ExecutorService",
        "java.util.concurrent.ThreadPoolExecutor",

        "java.io.ObjectInputStream",

        "java.io.File"
    );

    public static final Set<String> SUSPICIOUS_FILE_PATHS = Set.of(
        "c:/windows",
        "c:\\windows",
        "system32",
        "program files",
        "appdata",

        "/etc/",
        "/bin/",
        "/sbin/",
        "/usr/bin/",
        "/usr/sbin/",
        "/var/log/",
        "user.home"
    );

        /**
     * Methods that introduce untrusted, external data into the program.
     * The return values of these methods are considered "tainted".
     */
    public static final Set<String> TAINT_SOURCES = Set.of(
        "java.net.Socket.getInputStream",
        "java.nio.channels.SocketChannel.read",
        "java.io.FileInputStream.read"

    );

    /**
     * Methods that are dangerous if called with tainted data.
     * These are the "sinks" we want to protect.
     */
    public static final Set<String> SENSITIVE_SINKS = Set.of(
        "java.lang.Runtime.exec",
        "java.lang.ProcessBuilder.start",
        "java.io.File.new",
        "java.nio.file.Paths.get"
    );

    public static final Set<String> OBFUSCATION_METHODS = Set.of(
        "java.util.Base64.getDecoder"
    );

        /**
     * Regex patterns for detecting suspicious string literals.
     */
    public static final Pattern IP_ADDRESS_PATTERN =
        Pattern.compile("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b");

    /**
     * Regex patterns for detecting suspicious domains.
     * This is a simple regex and might have false positives.
     */
    public static final Pattern DOMAIN_PATTERN =
        Pattern.compile("\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,6}\\b");

    /**
     * Integer literals that are suspicious, often used for C2 connections.
     */
    public static final Set<Integer> SUSPICIOUS_PORTS = Set.of(
        1337,
        4444,
        6667,
        31337
    );
}