package org.glassfish.grizzly.http.slowattack;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 指纹统计管理器
 * 追踪每个指纹的违规次数和请求时间
 */
public class FingerprintStatisticsManager {

    private final ConcurrentHashMap<String, AtomicInteger> violationCounts;
    private final ConcurrentHashMap<String, Long> requestStartTimes;

    public FingerprintStatisticsManager() {
        this.violationCounts = new ConcurrentHashMap<>();
        this.requestStartTimes = new ConcurrentHashMap<>();
    }

    public void recordViolation(ClientFingerprint fingerprint) {
        if (fingerprint == null) {
            return;
        }

        String key = fingerprint.getFullKey();
        AtomicInteger counter = violationCounts.get(key);
        if (counter == null) {
            counter = new AtomicInteger(0);
            AtomicInteger existing = violationCounts.putIfAbsent(key, counter);
            if (existing != null) {
                counter = existing;
            }
        }
        counter.incrementAndGet();
    }

    public int getViolationCount(ClientFingerprint fingerprint) {
        if (fingerprint == null) {
            return 0;
        }

        String key = fingerprint.getFullKey();
        AtomicInteger count = violationCounts.get(key);
        return count != null ? count.get() : 0;
    }

    public void clearStatistics(ClientFingerprint fingerprint) {
        if (fingerprint == null) {
            return;
        }

        String key = fingerprint.getFullKey();
        violationCounts.remove(key);
        requestStartTimes.remove(key);
    }

    public void recordRequestStart(String key) {
        if (key == null || key.isEmpty()) {
            return;
        }

        requestStartTimes.put(key, System.nanoTime());
    }

    public boolean isTotalRequestTimeout(String key, long timeoutMs) {
        if (key == null || key.isEmpty()) {
            return false;
        }

        Long startTime = requestStartTimes.get(key);
        if (startTime == null) {
            return false;
        }

        long elapsedMs = (System.nanoTime() - startTime) / 1_000_000;
        return elapsedMs > timeoutMs;
    }

    public void recordRequestComplete(String key) {
        if (key == null || key.isEmpty()) {
            return;
        }

        requestStartTimes.remove(key);
    }

    public void clear() {
        violationCounts.clear();
        requestStartTimes.clear();
    }

    public int getTrackedFingerprintCount() {
        return violationCounts.size();
    }
}
