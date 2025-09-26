package org.example.malicious;

// A simple test application that tries to use a forbidden class.
public class MaliciousApp {
    public static void main(String[] args) {
        System.out.println("Malicious App: Trying to access Runtime...");
        try {
            // This line should be blocked by the SecureClassLoader
            Runtime.getRuntime().exec("calc.exe");
            System.out.println("Malicious App: Succeeded in getting Runtime. This should not happen!");
        } catch (Exception e) {
            System.out.println("Malicious App: Failed as expected. Error: " + e.getMessage());
        }
    }
}