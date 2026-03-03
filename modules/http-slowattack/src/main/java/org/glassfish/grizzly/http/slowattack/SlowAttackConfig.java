package org.glassfish.grizzly.http.slowattack;

import java.util.Collections;
import java.util.List;

/**
 * 慢请求攻击防护配置
 * 使用 Builder 模式创建不可变配置对象
 */
public final class SlowAttackConfig {

    // 默认值
    private static final long DEFAULT_HEADER_TIMEOUT = 5000;
    private static final long DEFAULT_BODY_TIMEOUT = 10000;
    private static final long DEFAULT_TOTAL_TIMEOUT = 30000;
    private static final long DEFAULT_BAN_DURATION = 300000;
    private static final int DEFAULT_SLOW_REQUEST_THRESHOLD = 5;
    private static final boolean DEFAULT_ENABLE_FINGERPRINTING = true;
    private static final boolean DEFAULT_INCLUDE_REQUEST_PATTERN = true;
    private static final boolean DEFAULT_NORMALIZE_URI = true;
    private static final LogLevel DEFAULT_LOG_LEVEL = LogLevel.DETAILED;

    private final long headerTimeout;
    private final long bodyTimeout;
    private final long totalTimeout;
    private final long banDuration;
    private final int slowRequestThreshold;
    private final List<String> whitelist;
    private final boolean enableFingerprinting;
    private final boolean includeRequestPattern;
    private final boolean normalizeUri;
    private final LogLevel logLevel;

    private SlowAttackConfig(Builder builder) {
        this.headerTimeout = builder.headerTimeout;
        this.bodyTimeout = builder.bodyTimeout;
        this.totalTimeout = builder.totalTimeout;
        this.banDuration = builder.banDuration;
        this.slowRequestThreshold = builder.slowRequestThreshold;
        this.whitelist = builder.whitelist != null
            ? Collections.unmodifiableList(builder.whitelist)
            : Collections.emptyList();
        this.enableFingerprinting = builder.enableFingerprinting;
        this.includeRequestPattern = builder.includeRequestPattern;
        this.normalizeUri = builder.normalizeUri;
        this.logLevel = builder.logLevel;
    }

    public static Builder builder() {
        return new Builder();
    }

    // Getters
    public long getHeaderTimeout() { return headerTimeout; }
    public long getBodyTimeout() { return bodyTimeout; }
    public long getTotalTimeout() { return totalTimeout; }
    public long getBanDuration() { return banDuration; }
    public int getSlowRequestThreshold() { return slowRequestThreshold; }
    public List<String> getWhitelist() { return whitelist; }
    public boolean isEnableFingerprinting() { return enableFingerprinting; }
    public boolean isIncludeRequestPattern() { return includeRequestPattern; }
    public boolean isNormalizeUri() { return normalizeUri; }
    public LogLevel getLogLevel() { return logLevel; }

    /**
     * 配置构建器
     */
    public static final class Builder {
        private long headerTimeout = DEFAULT_HEADER_TIMEOUT;
        private long bodyTimeout = DEFAULT_BODY_TIMEOUT;
        private long totalTimeout = DEFAULT_TOTAL_TIMEOUT;
        private long banDuration = DEFAULT_BAN_DURATION;
        private int slowRequestThreshold = DEFAULT_SLOW_REQUEST_THRESHOLD;
        private List<String> whitelist;
        private boolean enableFingerprinting = DEFAULT_ENABLE_FINGERPRINTING;
        private boolean includeRequestPattern = DEFAULT_INCLUDE_REQUEST_PATTERN;
        private boolean normalizeUri = DEFAULT_NORMALIZE_URI;
        private LogLevel logLevel = DEFAULT_LOG_LEVEL;

        public Builder headerTimeout(long headerTimeout) {
            this.headerTimeout = headerTimeout;
            return this;
        }

        public Builder bodyTimeout(long bodyTimeout) {
            this.bodyTimeout = bodyTimeout;
            return this;
        }

        public Builder totalTimeout(long totalTimeout) {
            this.totalTimeout = totalTimeout;
            return this;
        }

        public Builder banDuration(long banDuration) {
            this.banDuration = banDuration;
            return this;
        }

        public Builder slowRequestThreshold(int slowRequestThreshold) {
            this.slowRequestThreshold = slowRequestThreshold;
            return this;
        }

        public Builder whitelist(List<String> whitelist) {
            this.whitelist = whitelist;
            return this;
        }

        public Builder enableFingerprinting(boolean enableFingerprinting) {
            this.enableFingerprinting = enableFingerprinting;
            return this;
        }

        public Builder includeRequestPattern(boolean includeRequestPattern) {
            this.includeRequestPattern = includeRequestPattern;
            return this;
        }

        public Builder normalizeUri(boolean normalizeUri) {
            this.normalizeUri = normalizeUri;
            return this;
        }

        public Builder logLevel(LogLevel logLevel) {
            this.logLevel = logLevel;
            return this;
        }

        public SlowAttackConfig build() {
            // 验证配置
            if (headerTimeout <= 0) {
                throw new IllegalArgumentException("headerTimeout must be positive");
            }
            if (bodyTimeout <= 0) {
                throw new IllegalArgumentException("bodyTimeout must be positive");
            }
            if (totalTimeout <= 0) {
                throw new IllegalArgumentException("totalTimeout must be positive");
            }
            if (banDuration <= 0) {
                throw new IllegalArgumentException("banDuration must be positive");
            }
            if (slowRequestThreshold <= 0) {
                throw new IllegalArgumentException("slowRequestThreshold must be positive");
            }

            return new SlowAttackConfig(this);
        }
    }
}
