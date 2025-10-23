package org.example.analyzer;

import java.util.Set;
import java.util.regex.Pattern;

public class DenyList {

    /**
     * Regex-Pattern zum Erkennen von verdächtigen String-Literalen
     */
    public static final Pattern IP_ADDRESS_PATTERN =
            Pattern.compile("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b");

    /**
     * Regex-Pattern zum Erkennen von verdächtigen Domains
     * Das ist ein einfaches Regex und könnte falsche Treffer haben
     */
    public static final Pattern DOMAIN_PATTERN =
            Pattern.compile("\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,6}\\b");

    /**
     * Properties die oft für Fingerprinting geprüft werden
     */
    public static final Set<String> FINGERPRINTING_PROPERTIES = Set.of(
            "user.name",
            "os.name",
            "os.version",
            "java.vm.vendor",
            "java.vm.name"
    );

    /**
     * String-Literale die mit Sandboxes VMs oder Analyse-Tools zu tun haben
     */
    public static final Set<String> SUSPICIOUS_FINGERPRINTING_STRINGS = Set.of(
            // Benutzernamen
            "admin", "test", "sandbox", "user", "vagrant",
            // VM / Sandbox-Artefakte
            "vmware", "virtualbox", "vbox", "qemu", "hyperv", "parallels",
            "C:\\sandbox", "C:\\analysis",
            // Prozesse von Security-Tools
            "vmtoolsd.exe", "wireshark.exe", "procmon.exe", "fiddler.exe", "ollydbg.exe",
            // MAC-Präfixe (seltener Check im Java-Source aber möglich)
            "08:00:27", // VirtualBox
            "00:05:69", // VMware
            "00:0C:29", // VMware
            "00:1C:14", // Parallels
            "00:50:56"  // VMware
    );
}

