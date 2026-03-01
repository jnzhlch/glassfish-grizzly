# 慢请求攻击防护功能设计文档

**日期:** 2026-03-02
**状态:** 设计完成，待实现

## 1. 概述

本设计为 GlassFish Grizzly 添加慢请求攻击防护功能，用于防护 Slowloris 等慢速攻击，支持慢头部、慢主体、慢响应的全面防护。

### 1.1 目标

- 防护 HTTP 慢头部攻击
- 防护 HTTP 慢主体攻击
- 防护 HTTP 慢响应攻击
- 按 IP 统计并封禁恶意 IP
- 支持白名单
- 详细的日志记录

### 1.2 非目标

- 不做分布式防护（单机防护）
- 不持久化封禁列表（纯内存）
- 不做 DDoS 防护（仅慢请求攻击）

## 2. 架构设计

### 2.1 整体架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                         HTTPServerConfiguration                      │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ @SlowAttackProtection
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     SlowAttackProtectionFilter                       │
│                    (extends BaseFilter)                              │
│                                                                      │
│   handleRead() ──► 检测慢头部/慢主体                                │
│   handleWrite() ──► 检测慢响应                                      │
│   handleClose() ──► 清理资源                                        │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
            ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
            │ IpBanList    │ │IpWhitelist   │ │EventLogger   │
            │              │ │              │ │              │
            │ConcurrentMap │ │ConcurrentMap │ │Logger        │
            │IP -> Expire  │ │Set<String>   │ │              │
            └──────────────┘ └──────────────┘ └──────────────┘
                    │
                    ▼
            ┌──────────────────┐
            │IpStatisticsManager│
            │                   │
            │ConcurrentMap      │
            │IP -> SlowCount    │
            └──────────────────┘
```

### 2.2 Filter 链位置

```
Client → [ServerCodecFilter] → [SlowAttackProtectionFilter] → [HttpServerFilter] → Application
```

## 3. 配置设计

### 3.1 注解配置

```java
@SlowAttackProtection(
    headerTimeout = 3000,          // HTTP 头部接收间隔 (ms)
    bodyTimeout = 5000,            // 请求体接收间隔 (ms)
    totalTimeout = 20000,          // 整个请求完成时间 (ms)
    responseTimeout = 10000,       // 响应发送间隔 (ms)
    banDuration = 600000,          // IP 封禁时长 (ms)
    slowRequestThreshold = 5,      // 触发封禁的慢请求次数
    whitelist = {"127.0.0.1"},     // IP 白名单
    logLevel = LogLevel.DETAILED   // 日志级别
)
```

### 3.2 配置参数说明

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| headerTimeout | long | 5000ms | HTTP 头部接收的最大时间间隔 |
| bodyTimeout | long | 10000ms | 请求体接收的最大时间间隔 |
| totalTimeout | long | 30000ms | 整个请求完成的最大时间 |
| responseTimeout | long | 15000ms | 响应发送的最大时间间隔 |
| banDuration | long | 300000ms | IP 封禁时长 (5分钟) |
| slowRequestThreshold | int | 3 | 触发封禁的慢请求次数 |
| whitelist | String[] | {} | IP 白名单 |
| logLevel | LogLevel | DETAILED | 日志级别 |

## 4. 核心组件

### 4.1 SlowAttackProtectionFilter

核心过滤器，继承 `BaseFilter`：

- `handleRead()`: 检测慢头部和慢主体攻击
- `handleWrite()`: 检测慢响应攻击
- `handleClose()`: 清理连接相关资源

### 4.2 IpBanList

IP 封禁列表，纯内存存储：

- 使用 `ConcurrentHashMap<String, Long>` 存储
- 定时清理过期封禁记录
- 线程安全操作

### 4.3 IpWhitelist

IP 白名单：

- 使用 `ConcurrentHashMap.newKeySet()` 实现
- 支持运行时动态添加/删除

### 4.4 IpStatisticsManager

IP 慢请求统计管理器：

- 跟踪每个 IP 的慢请求数量
- 跟踪请求开始时间（用于总超时检测）

### 4.5 DetailedEventLogger

详细事件日志记录器：

- 记录所有慢请求事件
- 记录封禁事件
- 支持不同日志级别

## 5. 检测逻辑

### 5.1 慢头部检测

1. 记录头部开始接收时间
2. 每次读取时检查时间间隔
3. 超过 `headerTimeout` 则记录慢请求

### 5.2 慢主体检测

1. 记录每次 body chunk 接收时间
2. 检查相邻 chunk 的时间间隔
3. 超过 `bodyTimeout` 则记录慢请求

### 5.3 慢响应检测

1. 跟踪响应写入时间
2. 检查响应写入间隔
3. 超过 `responseTimeout` 则记录慢请求

### 5.4 封禁触发

1. 统计同一 IP 的慢请求数
2. 达到 `slowRequestThreshold` 时封禁
3. 封禁时长为 `banDuration`

## 6. 错误处理

### 6.1 异常场景

| 场景 | 处理方式 |
|------|----------|
| 无效 IP 地址 | 记录警告，放行连接 |
| 配置错误 | 记录错误，使用默认值 |
| 内存不足 | 清理过期统计，限制新连接 |
| 并发冲突 | CAS 操作，失败重试 |

### 6.2 降级策略

当内存使用率 > 90% 时：
- 增加检测阈值
- 减少日志输出
- 清理部分统计数据

## 7. 模块结构

```
modules/http-slowattack/
├── pom.xml
└── src/main/java/org/glassfish/grizzly/http/slowattack/
    ├── SlowAttackProtection.java           # 注解
    ├── SlowAttackConfig.java               # 配置类
    ├── SlowAttackProtectionFilter.java     # 核心过滤器
    ├── IpBanList.java                      # 封禁列表
    ├── IpWhitelist.java                    # 白名单
    ├── IpStatisticsManager.java            # 统计管理
    ├── DetailedEventLogger.java            # 日志
    ├── AttributeKeys.java                  # 属性键
    ├── AttackType.java                     # 攻击类型
    ├── SlowAttackResult.java               # 检测结果
    ├── ErrorHandler.java                   # 错误处理
    └── DegradationHandler.java             # 降级处理
```

## 8. 集成方式

### 8.1 注解方式（推荐）

```java
@SlowAttackProtection(
    headerTimeout = 3000,
    banDuration = 600000
)
public class MyServer {
    public static void main(String[] args) {
        HttpServer server = HttpServer.createSimpleServer();
        // 自动启用防护
    }
}
```

### 8.2 编程方式

```java
SlowAttackConfig config = SlowAttackConfig.builder()
    .headerTimeout(3000)
    .banDuration(600000)
    .build();

SlowAttackProtectionFilter filter = new SlowAttackProtectionFilter(config);
server.getListener("grizzly").getFilterChain().add(filter);
```

## 9. 日志示例

```
[SLOW-ATTACK] Slow header detected from IP: 192.168.1.50, elapsed: 5200ms
[SLOW-ATTACK] Slow request recorded - IP: 192.168.1.50, count: 1/3
[SLOW-ATTACK] IP BANNED - IP: 192.168.1.50, slow count: 3
[SLOW-ATTACK] Ban enforced - rejecting connection from banned IP: 192.168.1.50
```

## 10. 测试策略

- 单元测试：各个组件独立测试
- 集成测试：端到端攻击模拟测试
- 性能测试：验证性能影响 < 5%

## 11. 后续工作

创建详细实现计划 (implementation plan)
