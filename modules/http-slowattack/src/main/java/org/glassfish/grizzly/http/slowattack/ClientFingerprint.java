package org.glassfish.grizzly.http.slowattack;

import java.util.Objects;

/**
 * 客户端指纹数据类
 * 使用 IP + User-Agent + Request Pattern 组合来唯一标识客户端
 */
public final class ClientFingerprint {

    private final String ipAddress;
    private final String userAgent;
    private final String requestPattern;
    private final String simplifiedKey;
    private final String fullKey;

    /**
     * 创建客户端指纹
     *
     * @param ipAddress 客户端 IP 地址
     * @param userAgent User-Agent 字符串
     * @param requestPattern 请求模式 (METHOD:normalized_uri)
     */
    public ClientFingerprint(String ipAddress, String userAgent, String requestPattern) {
        this.ipAddress = ipAddress != null ? ipAddress : "unknown";
        this.userAgent = userAgent != null ? userAgent : "unknown";
        this.requestPattern = requestPattern != null ? requestPattern : "unknown";

        // 构建简化指纹：IP + User-Agent（用于封禁列表）
        this.simplifiedKey = this.ipAddress + "|" + this.userAgent;

        // 构建完整指纹：简化指纹 + 请求模式（用于统计）
        this.fullKey = this.simplifiedKey + "|" + this.requestPattern;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public String getRequestPattern() {
        return requestPattern;
    }

    /**
     * 获取简化指纹键，用于封禁列表
     * 同一 IP+UA 的所有请求共享封禁状态
     */
    public String getSimplifiedKey() {
        return simplifiedKey;
    }

    /**
     * 获取完整指纹键，用于违规统计
     * 区分同一 IP+UA 的不同攻击模式
     */
    public String getFullKey() {
        return fullKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ClientFingerprint that = (ClientFingerprint) o;
        return Objects.equals(fullKey, that.fullKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(fullKey);
    }

    @Override
    public String toString() {
        return "ClientFingerprint{" +
                "ip='" + ipAddress + '\'' +
                ", ua='" + userAgent + '\'' +
                ", pattern='" + requestPattern + '\'' +
                '}';
    }
}
