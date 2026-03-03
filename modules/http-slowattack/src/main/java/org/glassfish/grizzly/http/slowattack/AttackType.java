package org.glassfish.grizzly.http.slowattack;

/**
 * 慢请求攻击类型枚举
 */
public enum AttackType {
    /**
     * 慢头部攻击 - 客户端极慢地发送 HTTP 头部
     */
    SLOW_HEADER,

    /**
     * 慢主体攻击 - 客户端极慢地发送请求体
     */
    SLOW_BODY,

    /**
     * 慢响应攻击 - 客户端极慢地读取响应
     */
    SLOW_RESPONSE,

    /**
     * 总请求超时 - 整个请求耗时过长
     */
    TOTAL_TIMEOUT
}
