package org.example.malicious;

public class MaliciousApp {
    public static void main(String[] args) {
        System.out.println("Malicious App: Trying to access Runtime...");
        try {
            Runtime.getRuntime().exec("calc.exe");
            System.out.println("Malicious App: Succeeded in getting Runtime. This should not happen!");
        } catch (Exception e) {
            System.out.println("Malicious App: Failed as expected. Error: " + e.getMessage());
        }
    }
}