package org.glassfish.grizzly.http.slowattack;

import java.io.PrintStream;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 详细事件日志记录器
 * 根据 LogLevel 记录不同详细程度的日志
 */
public class DetailedEventLogger {

    private static final Logger LOGGER = Logger.getLogger(DetailedEventLogger.class.getName());
    private static final String LOG_PREFIX = "[SLOW-ATTACK] ";

    private final LogLevel logLevel;
    private final PrintStream output;

    public DetailedEventLogger(LogLevel logLevel, PrintStream output) {
        this.logLevel = logLevel != null ? logLevel : LogLevel.DETAILED;
        this.output = output != null ? output : System.out;
    }

    public DetailedEventLogger(LogLevel logLevel) {
        this(logLevel, System.out);
    }

    public void logSlowHeaderDetected(ClientFingerprint fingerprint, long elapsedMs) {
        if (shouldLog()) {
            String message = String.format("%sSlow header detected - fingerprint: %s, elapsed: %dms",
                LOG_PREFIX, fingerprint.getSimplifiedKey(), elapsedMs);
            log(message);
        }
    }

    public void logSlowBodyDetected(ClientFingerprint fingerprint, long elapsedMs) {
        if (shouldLog()) {
            String message = String.format("%sSlow body detected - fingerprint: %s, elapsed: %dms",
                LOG_PREFIX, fingerprint.getSimplifiedKey(), elapsedMs);
            log(message);
        }
    }

    public void logSlowResponseDetected(ClientFingerprint fingerprint, long elapsedMs) {
        if (shouldLog()) {
            String message = String.format("%sSlow response detected - fingerprint: %s, elapsed: %dms",
                LOG_PREFIX, fingerprint.getSimplifiedKey(), elapsedMs);
            log(message);
        }
    }

    public void logTotalTimeout(ClientFingerprint fingerprint, long elapsedMs) {
        if (shouldLog()) {
            String message = String.format("%sTotal request timeout - fingerprint: %s, elapsed: %dms",
                LOG_PREFIX, fingerprint.getSimplifiedKey(), elapsedMs);
            log(message);
        }
    }

    public void logViolationRecorded(ClientFingerprint fingerprint, int count, int threshold) {
        if (shouldLog()) {
            String message = String.format("%sSlow request recorded - fingerprint: %s, count: %d/%d",
                LOG_PREFIX, fingerprint.getFullKey(), count, threshold);
            log(message);
        }
    }

    public void logFingerprintBanned(String simplifiedKey, int violations, long banDuration) {
        if (logLevel != LogLevel.OFF) {
            String message = String.format("%sFingerprint BANNED - fingerprint: %s, violations: %d, ban duration: %dms",
                LOG_PREFIX, simplifiedKey, violations, banDuration);
            log(message);
            LOGGER.warning(message);
        }
    }

    public void logBanEnforced(String simplifiedKey) {
        if (logLevel != LogLevel.OFF) {
            String message = String.format("%sBan enforced - rejecting connection from banned fingerprint: %s",
                LOG_PREFIX, simplifiedKey);
            log(message);
            LOGGER.info(message);
        }
    }

    public void logWhitelistSkipped(String ipAddress) {
        if (logLevel == LogLevel.DETAILED) {
            String message = String.format("%sRequest skipped - IP whitelisted: %s", LOG_PREFIX, ipAddress);
            log(message);
        }
    }

    public void logError(String message, Throwable t) {
        if (logLevel != LogLevel.OFF) {
            String errorMessage = LOG_PREFIX + "ERROR: " + message;
            log(errorMessage);
            LOGGER.log(Level.WARNING, errorMessage, t);
        }
    }

    private boolean shouldLog() {
        return logLevel == LogLevel.DETAILED || logLevel == LogLevel.BASIC;
    }

    private void log(String message) {
        output.println(message);
    }
}
