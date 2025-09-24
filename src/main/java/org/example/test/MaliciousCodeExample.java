package org.example.test;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method; // Forbidden package

public class MaliciousCodeExample {

    public void executeCommand() {
        try {
            // Forbidden class usage and method call
            Runtime.getRuntime().exec("calc.exe");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void createFile() {
        // Forbidden class import
        File f = new File("deleteme.txt");
        f.delete();
    }

    public void terminate() {
        // Forbidden method call
        System.exit(1);
    }

    public void useReflection() throws Exception {
        // Usage of forbidden package
        Class<?> clazz = String.class;
        Method method = clazz.getMethod("toUpperCase");
        System.out.println(method.invoke("hello"));
    }
}