package org.glassfish.grizzly.http.slowattack;

import org.glassfish.grizzly.attributes.Attribute;
import org.glassfish.grizzly.attributes.AttributeBuilder;

/**
 * 连接属性键定义
 * 用于在 FilterChainContext 中存储请求处理状态
 */
public final class AttributeKeys {

    private AttributeKeys() {
        // 防止实例化
    }

    /**
     * 请求开始时间戳（纳秒）
     */
    public static final Attribute<Long> REQUEST_START_TIME =
        AttributeBuilder.DEFAULT_ATTRIBUTE_BUILDER.createAttribute("slow-attack.request-start-time");

    /**
     * 上次读取时间戳（纳秒）
     */
    public static final Attribute<Long> LAST_READ_TIME =
        AttributeBuilder.DEFAULT_ATTRIBUTE_BUILDER.createAttribute("slow-attack.last-read-time");

    /**
     * 上次写入时间戳（纳秒）
     */
    public static final Attribute<Long> LAST_WRITE_TIME =
        AttributeBuilder.DEFAULT_ATTRIBUTE_BUILDER.createAttribute("slow-attack.last-write-time");

    /**
     * 头部接收开始时间戳（纳秒）
     */
    public static final Attribute<Long> HEADER_START_TIME =
        AttributeBuilder.DEFAULT_ATTRIBUTE_BUILDER.createAttribute("slow-attack.header-start-time");

    /**
     * 请求体接收开始时间戳（纳秒）
     */
    public static final Attribute<Long> BODY_START_TIME =
        AttributeBuilder.DEFAULT_ATTRIBUTE_BUILDER.createAttribute("slow-attack.body-start-time");

    /**
     * 响应写入开始时间戳（纳秒）
     */
    public static final Attribute<Long> RESPONSE_START_TIME =
        AttributeBuilder.DEFAULT_ATTRIBUTE_BUILDER.createAttribute("slow-attack.response-start-time");

    /**
     * 客户端指纹
     */
    public static final Attribute<ClientFingerprint> CLIENT_FINGERPRINT =
        AttributeBuilder.DEFAULT_ATTRIBUTE_BUILDER.createAttribute("slow-attack.client-fingerprint");
}
