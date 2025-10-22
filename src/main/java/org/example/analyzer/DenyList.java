package org.example.analyzer;

import java.util.Set;
import java.util.regex.Pattern;

public class DenyList {

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
     * Properties often checked for fingerprinting.
     */
    public static final Set<String> FINGERPRINTING_PROPERTIES = Set.of(
            "user.name",
            "os.name",
            "os.version",
            "java.vm.vendor",
            "java.vm.name"
    );

    /**
     * String literals associated with sandboxes, VMs, or analysis tools.
     */
    public static final Set<String> SUSPICIOUS_FINGERPRINTING_STRINGS = Set.of(
            // Usernames
            "admin", "test", "sandbox", "user", "vagrant",
            // VM / Sandbox Artifacts
            "vmware", "virtualbox", "vbox", "qemu", "hyperv", "parallels",
            "C:\\sandbox", "C:\\analysis",
            // Security Tools Processes
            "vmtoolsd.exe", "wireshark.exe", "procmon.exe", "fiddler.exe", "ollydbg.exe",
            // MAC Prefixes (less common check in Java source, but possible)
            "08:00:27", // VirtualBox
            "00:05:69", // VMware
            "00:0C:29", // VMware
            "00:1C:14", // Parallels
            "00:50:56"  // VMware
    );
}