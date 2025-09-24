package org.example.test;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicLong;

public class SimpleMiner {

    public static void main(String[] args) {
        // 1. Concurrency: Use all available CPU cores.
        int coreCount = Runtime.getRuntime().availableProcessors();
        ThreadPoolExecutor executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(coreCount);
        System.out.println("Starting miner with " + coreCount + " threads.");

        // The "difficulty" is a very large number. We need our hash to be smaller than this.
        final BigInteger targetDifficulty = new BigInteger("0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16);

        // Start a mining task on each thread.
        for (int i = 0; i < coreCount; i++) {
            executor.submit(new MiningTask(targetDifficulty));
        }
    }

    static class MiningTask implements Runnable {
        private final BigInteger target;
        private final AtomicLong nonce = new AtomicLong(0);

        MiningTask(BigInteger target) {
            this.target = target;
        }

        @Override
        public void run() {
            String blockData = "ExampleBlockData";

            // 2. Infinite Loop: Keep hashing forever.
            while (true) {
                try {
                    long currentNonce = nonce.getAndIncrement();
                    String dataToHash = blockData + currentNonce;

                    // 3. Hashing: Use MessageDigest for SHA-256.
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] hashBytes = digest.digest(dataToHash.getBytes());

                    // 4. BigInteger: Convert hash to a number for comparison.
                    BigInteger hashAsInt = new BigInteger(1, hashBytes);

                    // 5. Comparison: Check if we "found" a valid hash.
                    if (hashAsInt.compareTo(target) < 0) {
                        System.out.println("Block found! Nonce: " + currentNonce + ", Hash: " + hashAsInt.toString(16));
                        // In a real miner, this would stop and report the result.
                    }

                    // A simple check to prevent the example from running uncontrollably.
                    if (Thread.currentThread().isInterrupted()) {
                        break;
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
