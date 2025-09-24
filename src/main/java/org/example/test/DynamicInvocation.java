package org.example.test;

import java.lang.reflect.Method;

public class DynamicInvocation {

    // This method should be flagged for using reflection to access a dangerous method.
    public void executeViaReflection() {
        try {
            // Malware hides dangerous calls by looking them up as strings.
            Class<?> runtimeClass = Class.forName("java.lang.Runtime");
            Method getRuntimeMethod = runtimeClass.getMethod("getRuntime");
            Object runtimeInstance = getRuntimeMethod.invoke(null);

            // Find the "exec" method, which takes a String.
            Method execMethod = runtimeClass.getMethod("exec", String.class);

            // Execute a command, like "calc.exe" on Windows.
            execMethod.invoke(runtimeInstance, "calc.exe");

        } catch (Exception e) {
            // Ignored for this example.
        }
    }
}