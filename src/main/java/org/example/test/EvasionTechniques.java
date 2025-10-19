package org.example.test;

public class EvasionTechniques {

    /**
     * This method should be flagged for using a common anti-debugging/sandbox detection trick.
     * It checks the time before and after a simple operation. If the elapsed time is too long
     * (because a debugger was attached or the sandbox is slow), the malware might exit.
     */
    public void antiSandboxTimingCheck() {
        long startTime = System.nanoTime();

        // A simple, fast operation
        Math.sqrt(25.0);

        long endTime = System.nanoTime();

        if (endTime - startTime > 1_000_000) { // Check if it took longer than 1ms
            // In real malware, this might be System.exit(0)
            System.out.println("Sandbox detected, exiting.");
        }
    }

    /**
     * This method should be flagged for unusually high cyclomatic complexity.
     * It's a nonsensical chain of if/else and switch statements designed to be
     * hard for humans and static analysis tools to follow.
     * @param input An integer to drive the complex path.
     * @return A calculated integer.
     */
    public int highlyComplexMethod(int input) {
        int result = 0;
        if (input > 10) {
            result++;
            for (int i = 0; i < input; i++) {
                if (i % 2 == 0) {
                    result += 2;
                } else {
                    result -= 1;
                }
            }
        } else if (input > 5) {
            result += 5;
            switch (input) {
                case 6: result *= 2; break;
                case 7: result *= 3; break;
                default: result -= 10;
            }
        } else {
            if (input == 1) {
                result = 100;
            } else if (input == 2) {
                result = 200;
            } else {
                result = 300;
            }
        }
        while (result > 50) {
            result /= 2;
        }
        return result; // Complexity points: if(2), for(1), if(2), else if(1), switch(1), if(2), while(1) = 10
    }
}
