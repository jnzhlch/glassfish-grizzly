package org.glassfish.grizzly.http.slowattack;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.glassfish.grizzly.Connection;
import org.glassfish.grizzly.filterchain.BaseFilter;
import org.glassfish.grizzly.filterchain.FilterChain;
import org.glassfish.grizzly.filterchain.FilterChainContext;
import org.glassfish.grizzly.filterchain.NextAction;
import org.glassfish.grizzly.http.HttpContent;
import org.glassfish.grizzly.http.HttpHeader;
import org.glassfish.grizzly.http.HttpRequestPacket;
import org.glassfish.grizzly.http.util.Header;

/**
 * 慢请求攻击防护过滤器
 * 检测并防护 HTTP 慢头部、慢主体、慢响应攻击
 */
public class SlowAttackProtectionFilter extends BaseFilter {

    private static final Logger LOGGER = Logger.getLogger(SlowAttackProtectionFilter.class.getName());

    private final SlowAttackConfig config;
    private final BanManager banManager;
    private final WhitelistManager whitelistManager;
    private final FingerprintStatisticsManager statisticsManager;
    private final DetailedEventLogger eventLogger;

    public SlowAttackProtectionFilter(SlowAttackConfig config) {
        if (config == null) {
            throw new IllegalArgumentException("config cannot be null");
        }

        this.config = config;
        this.banManager = new BanManager(config.getBanDuration());
        this.whitelistManager = new WhitelistManager(
            config.getWhitelist().toArray(new String[0])
        );
        this.statisticsManager = new FingerprintStatisticsManager();
        this.eventLogger = new DetailedEventLogger(config.getLogLevel());

        LOGGER.info("SlowAttackProtectionFilter initialized with config: " +
                  "headerTimeout=" + config.getHeaderTimeout() +
                  ", bodyTimeout=" + config.getBodyTimeout() +
                  ", banDuration=" + config.getBanDuration() +
                  ", threshold=" + config.getSlowRequestThreshold());
    }

    @Override
    public NextAction handleRead(FilterChainContext ctx) throws IOException {
        Connection connection = ctx.getConnection();
        Object message = ctx.getMessage();

        if (!(message instanceof HttpContent)) {
            return ctx.getInvokeAction();
        }

        HttpContent httpContent = (HttpContent) message;
        HttpHeader httpHeader = httpContent.getHttpHeader();

        if (!(httpHeader instanceof HttpRequestPacket)) {
            return ctx.getInvokeAction();
        }

        HttpRequestPacket request = (HttpRequestPacket) httpHeader;

        ClientFingerprint fingerprint = buildFingerprint(request, connection);

        if (whitelistManager.isWhitelisted(fingerprint.getIpAddress())) {
            eventLogger.logWhitelistSkipped(fingerprint.getIpAddress());
            return ctx.getInvokeAction();
        }

        if (banManager.isBanned(fingerprint.getSimplifiedKey())) {
            eventLogger.logBanEnforced(fingerprint.getSimplifiedKey());
            connection.close();
            return ctx.getStopAction();
        }

        SlowAttackResult result = detectSlowRequest(fingerprint, ctx, request);

        if (result.isAttack()) {
            handleViolation(fingerprint, result);
        }

        return ctx.getInvokeAction();
    }

    @Override
    public NextAction handleWrite(FilterChainContext ctx) throws IOException {
        detectSlowResponse(ctx);
        return ctx.getInvokeAction();
    }

    @Override
    public NextAction handleClose(FilterChainContext ctx) throws IOException {
        cleanupConnectionAttributes(ctx);
        return ctx.getStopAction();
    }

    @Override
    public void onAdded(FilterChain filterChain) {
        LOGGER.info("SlowAttackProtectionFilter added to filter chain");
    }

    @Override
    public void onRemoved(FilterChain filterChain) {
        LOGGER.info("SlowAttackProtectionFilter removed from filter chain, shutting down...");
        shutdown();
    }

    private ClientFingerprint buildFingerprint(HttpRequestPacket request, Connection connection) {
        try {
            String ipAddress = request.getRemoteAddress();
            String userAgent = request.getHeader(Header.UserAgent);
            String method = request.getMethod().toString();
            String uri = request.getRequestURI();

            return FingerprintBuilder.build(ipAddress, userAgent, method, uri);
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to build fingerprint, using IP only", e);
            String ipAddress = connection.getPeerAddress().toString();
            return new ClientFingerprint(ipAddress, "unknown", "unknown");
        }
    }

    private SlowAttackResult detectSlowRequest(ClientFingerprint fingerprint,
                                              FilterChainContext ctx,
                                              HttpRequestPacket request) {
        long now = System.nanoTime();

        Long headerStartTime = AttributeKeys.HEADER_START_TIME.get(ctx.getConnection());
        if (headerStartTime == null) {
            AttributeKeys.HEADER_START_TIME.set(ctx.getConnection(), now);
        } else {
            long headerElapsedMs = (now - headerStartTime) / 1_000_000;
            if (headerElapsedMs > config.getHeaderTimeout()) {
                eventLogger.logSlowHeaderDetected(fingerprint, headerElapsedMs);
                return SlowAttackResult.attack(AttackType.SLOW_HEADER, headerElapsedMs);
            }
        }

        if (request.getContentLength() > 0) {
            Long bodyStartTime = AttributeKeys.BODY_START_TIME.get(ctx.getConnection());
            if (bodyStartTime == null) {
                AttributeKeys.BODY_START_TIME.set(ctx.getConnection(), now);
            } else {
                Long lastReadTime = AttributeKeys.LAST_READ_TIME.get(ctx.getConnection());
                long lastRead = lastReadTime != null ? lastReadTime : bodyStartTime;
                long bodyElapsedMs = (now - lastRead) / 1_000_000;

                if (bodyElapsedMs > config.getBodyTimeout()) {
                    eventLogger.logSlowBodyDetected(fingerprint, bodyElapsedMs);
                    return SlowAttackResult.attack(AttackType.SLOW_BODY, bodyElapsedMs);
                }
            }
        }

        AttributeKeys.LAST_READ_TIME.set(ctx.getConnection(), now);

        if (statisticsManager.isTotalRequestTimeout(fingerprint.getFullKey(), config.getTotalTimeout())) {
            eventLogger.logTotalTimeout(fingerprint, config.getTotalTimeout());
            return SlowAttackResult.attack(AttackType.TOTAL_TIMEOUT, config.getTotalTimeout());
        }

        return SlowAttackResult.noAttack();
    }

    private void detectSlowResponse(FilterChainContext ctx) {
        Connection connection = ctx.getConnection();
        long now = System.nanoTime();

        Long responseStartTime = AttributeKeys.RESPONSE_START_TIME.get(connection);
        if (responseStartTime == null) {
            AttributeKeys.RESPONSE_START_TIME.set(connection, now);
        }

        AttributeKeys.LAST_WRITE_TIME.set(connection, now);
    }

    private void handleViolation(ClientFingerprint fingerprint, SlowAttackResult result) {
        statisticsManager.recordViolation(fingerprint);
        int violationCount = statisticsManager.getViolationCount(fingerprint);

        eventLogger.logViolationRecorded(fingerprint, violationCount, config.getSlowRequestThreshold());

        if (violationCount >= config.getSlowRequestThreshold()) {
            banManager.ban(fingerprint.getSimplifiedKey());
            eventLogger.logFingerprintBanned(
                fingerprint.getSimplifiedKey(),
                violationCount,
                config.getBanDuration()
            );
            statisticsManager.clearStatistics(fingerprint);
        }
    }

    private void cleanupConnectionAttributes(FilterChainContext ctx) {
        Connection connection = ctx.getConnection();

        AttributeKeys.HEADER_START_TIME.remove(connection);
        AttributeKeys.BODY_START_TIME.remove(connection);
        AttributeKeys.RESPONSE_START_TIME.remove(connection);
        AttributeKeys.LAST_READ_TIME.remove(connection);
        AttributeKeys.LAST_WRITE_TIME.remove(connection);
        AttributeKeys.CLIENT_FINGERPRINT.remove(connection);
    }

    public void shutdown() {
        banManager.shutdown();
        statisticsManager.clear();
    }

    public int getBannedCount() {
        return banManager.getBannedCount();
    }

    public int getTrackedFingerprintCount() {
        return statisticsManager.getTrackedFingerprintCount();
    }
}
