package org.glassfish.grizzly.http.slowattack;

/**
 * 日志级别枚举
 */
public enum LogLevel {
    /**
     * 关闭日志
     */
    OFF,

    /**
     * 基础日志 - 仅记录封禁事件
     */
    BASIC,

    /**
     * 详细日志 - 记录所有检测事件
     */
    DETAILED
}
