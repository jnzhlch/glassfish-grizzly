# 慢请求攻击防护功能需求文档

| 文档版本 | 1.0 |
|---------|-----|
| 创建日期 | 2026-03-03 |
| 适用版本 | Grizzly 2.4.x |
| 状态 | 已实现 |

---

## 1. 文档概述

### 1.1 目的

本文档详细描述 GlassFish Grizzly 2.4.x 分支中实现的 HTTP 慢请求攻击防护功能的需求规格。该功能旨在检测并防御慢速 HTTP 攻击（Slow HTTP Attack），保护服务器资源不被恶意耗尽。

### 1.2 背景慢速 HTTP 攻击是一种应用层 DoS 攻击，攻击者通过极慢的速度发送 HTTP 请求或读取响应，长期占用服务器连接资源，最终导致服务器无法处理正常请求。

主要的慢速攻击类型包括：
- **慢头部攻击（Slow Headers）**：客户端极慢地发送 HTTP 头部
- **慢主体攻击（Slow Body）**：客户端极慢地发送请求体
- **慢响应攻击（Slow Response）**：客户端极慢地读取响应

### 1.3 适用范围
- Grizzly HTTP Server 2.4.x 及以上版本
- Java 17+ 运行环境
- 适用于所有基于 Grizzly 的 HTTP 服务

---

## 2. 功能需求

### 2.1 核心检测能力

#### REQ-2.1.1 慢头部检测

系统必须能够检测客户端发送 HTTP 头部的时间是否超过预设阈值。

| 需求属性 | 值 |
|---------|-----|
| 优先级 | P0 (必须) |
| 默认超时 | 5000ms |
| 可配置 | 是 |
| 检测精度 | 毫秒级 |

**验收标准：**
- 当头部传输时间超过配置的超时值时，触发违规记录
- 能够区分正常的慢速网络连接和恶意攻击
- 检测不应影响正常请求的处理性能

#### REQ-2.1.2 慢主体检测

系统必须能够检测客户端发送请求体的时间是否超过预设阈值。

| 需求属性 | 值 |
|---------|-----|
| 优先级 | P0 (必须) |
| 默认超时 | 10000ms |
| 可配置 | 是 |
| 检测范围 | 每次数据读取间隔 |

**验收标准：**
- 仅对包含请求体的请求进行检测
- 检测两次连续读取操作之间的时间间隔
- 当间隔超过配置值时，触发违规记录

#### REQ-2.1.3 慢响应检测

系统必须能够检测客户端读取响应的缓慢程度。

| 需求属性 | 值 |
|---------|-----|
| 优先级 | P1 (重要) |
| 默认超时 | 继承 bodyTimeout |
| 可配置 | 是 |

**验收标准：**
- 跟踪响应写入的时间间隔
- 检测客户端是否及时读取响应数据
- 记录异常的慢响应行为

#### REQ-2.1.4 总请求超时检测

系统必须能够检测整个请求的生命周期是否超过预设的总超时时间。

| 需求属性 | 值 |
|---------|-----|
| 优先级 | P0 (必须) |
| 默认超时 | 30000ms |
| 可配置 | 是 |

**验收标准：**
- 从请求开始到完成的总时间监控
- 超过总超时时间时触发违规记录
- 与其他超时检测独立工作

### 2.2 客户端识别

#### REQ-2.2.1 指纹生成

系统必须基于多个维度生成唯一的客户端指纹。

| 指纹组成部分 | 说明 |
|------------|------|
| IP 地址 | 客户端 IP 地址 |
| User-Agent | HTTP User-Agent 头部 |
| 请求模式 | HTTP 方法 + 归一化后的 URI |

**验收标准：**
- 指纹必须唯一标识客户端
- 支持完整指纹（用于统计）和简化指纹（用于封禁）
- 归一化处理 URI 以避免路径变体绕过

#### REQ-2.2.2 URI 归一化

系统必须对请求 URI 进行归一化处理。

| 归一化操作 | 说明 |
|----------|------|
| 路径合并 | 合并连续的 `/` |
| 默认文档处理 | 处理 `/` 和 `/index.html` |
| 查询参数排序 | 统一参数顺序 |
| 大小写处理 | 对路径部分进行规范化 |

**验收标准：**
- `/path/` 和 `/path` 应被视为相同路径
- `/path?a=1&b=2` 和 `/path?b=2&a=1` 应被视为相同请求
- 支持可配置的归一化级别

### 2.3 违规处理

#### REQ-2.3.1 违规计数

系统必须追踪每个客户端指纹的违规次数。

| 需求属性 | 值 |
|---------|-----|
| 优先级 | P0 (必须) |
| 默认阈值 | 5 次 |
| 可配置 | 是 |
| 计数范围 | 按完整指纹 |

**验收标准：**
- 每次检测到慢请求行为时增加计数
- 达到阈值时触发封禁
- 计数基于完整指纹（包含请求模式）

#### REQ-2.3.2 自动封禁

系统必须在客户端违规次数达到阈值时自动封禁。

| 需求属性 | 值 |
|---------|-----|
| 优先级 | P0 (必须) |
| 默认封禁时长 | 300000ms (5分钟) |
| 可配置 | 是 |
| 封禁范围 | 简化指纹 (IP + UA) |

**验收标准：**
- 达到违规阈值时立即封禁
- 封禁后拒绝该指纹的所有新连接
- 封禁基于简化指纹，影响同一 IP+UA 的所有请求
- 封禁时长到期后自动解封

#### REQ-2.3.3 封禁过期清理

系统必须定期清理过期的封禁记录。

| 需求属性 | 值 |
|---------|-----|
| 优先级 | P0 (必须) |
| 清理间隔 | 60000ms (1分钟) |
| 实现方式 | 后台定时任务 |

**验收标准：**
- 每分钟执行一次过期清理
- 自动移除到期的封禁记录
- 不影响正在进行的封禁

### 2.4 白名单

#### REQ-2.4.1 IP 白名单

系统必须支持 IP 地址白名单功能，白名单内的请求不受防护限制。

| 支持格式 | 说明 |
|---------|------|
| 精确 IP | 如 `192.168.1.100` |
| CIDR | 如 `192.168.1.0/24` |
| 通配符 | 如 `192.168.1.*` |

**验收标准：**
- 白名单检查优先于所有其他检测
- 支持运行时动态添加/移除
- 白名单匹配不影响性能

#### REQ-2.4.2 CIDR 匹配

系统必须正确支持 CIDR 格式的 IP 范围匹配。

| 需求属性 | 值 |
|---------|-----|
| 优先级 | P1 (重要) |
| 支持 IPv4 | 是 |
| 支持 IPv6 | 是 |

**验收标准：**
- 正确解析 CIDR 表示法
- 准确匹配 IP 范围
- 支持任意前缀长度

### 2.5 日志记录

#### REQ-2.5.1 分级日志

系统必须支持多级日志记录。

| 日志级别 | 记录内容 |
|---------|---------|
| OFF | 仅记录严重错误 |
| BASIC | 记录封禁事件 |
| DETAILED | 记录所有检测事件 |

**验收标准：**
- 默认级别为 DETAILED
- 可通过配置调整
- 不影响业务逻辑

#### REQ-2.5.2 事件类型

系统必须记录以下类型的事件：

| 事件类型 | 日志级别 | 说明 |
|---------|---------|------|
| 慢头部检测 | DETAILED | 头部超时事件 |
| 慢主体检测 | DETAILED | 主体超时事件 |
| 慢响应检测 | DETAILED | 响应超时事件 |
| 总超时检测 | DETAILED | 总请求超时 |
| 违规记录 | DETAILED | 违规计数更新 |
| 指纹封禁 | BASIC+ | 封禁执行事件 |
| 封禁执行 | BASIC+ | 拒绝连接事件 |
| 白名单跳过 | DETAILED | 白名单跳过记录 |

**验收标准：**
- 所有日志包含统一前缀 `[SLOW-ATTACK]`
- 关键事件同时输出到 JUL Logger
- 日志包含足够的上下文信息用于分析

### 2.6 配置管理

#### REQ-2.6.1 Builder 模式配置

系统必须使用 Builder 模式提供类型安全的配置方式。

| 配置属性 | 类型 | 默认值 |
|---------|------|-------|
| headerTimeout | long | 5000ms |
| bodyTimeout | long | 10000ms |
| totalTimeout | long | 30000ms |
| banDuration | long | 300000ms |
| slowRequestThreshold | int | 5 |
| whitelist | List<String> | 空列表 |
| enableFingerprinting | boolean | true |
| includeRequestPattern | boolean | true |
| normalizeUri | boolean | true |
| logLevel | LogLevel | DETAILED |

**验收标准：**
- 所有配置项都有合理的默认值
- 配置对象不可变
- 构建时验证参数合法性
- 非法参数抛出 IllegalArgumentException

### 2.7 性能要求

#### REQ-2.7.1 性能开销

防护功能对正常请求的性能影响必须最小化。

| 需求属性 | 目标值 |
|---------|--------|
| 延迟增加 | < 5% |
| 内存开销 | < 10MB per 10K 连接 |
| CPU 开销 | < 2% |

**验收标准：**
- 通过性能基准测试验证
- 在高并发场景下稳定运行
- 不影响 Grizzly 的核心性能

#### REQ-2.7.2 并发安全

系统必须在多线程环境下安全运行。

| 需求属性 | 值 |
|---------|-----|
| 线程模型 | 无锁并发 |
| 数据结构 | ConcurrentHashMap |
| 原子操作 | AtomicInteger |

**验收标准：**
- 无竞态条件
- 无死锁风险
- 支持高并发访问

---

## 3. 非功能需求

### 3.1 可靠性

| 需求项 | 说明 |
|-------|------|
| 故障恢复 | 组件异常不应影响服务器核心功能 |
| 优雅关闭 | 支持优雅关闭，清理所有资源 |
| 内存管理 | 自动清理过期数据，防止内存泄漏 |

### 3.2 可维护性

| 需求项 | 说明 |
|-------|------|
| 代码结构 | 清晰的模块划分，单一职责 |
| 测试覆盖 | 单元测试覆盖率 > 80% |
| 文档 | 完整的 API 文档和使用示例 |

### 3.3 可扩展性

| 需求项 | 说明 |
|-------|------|
| 接口设计 | 预留扩展点，支持自定义检测逻辑 |
| 配置扩展 | 配置结构支持新增参数 |

---

## 4. API 定义

### 4.1 核心过滤器

```java
public class SlowAttackProtectionFilter extends BaseFilter {

    // 构造函数
    public SlowAttackProtectionFilter(SlowAttackConfig config)

    // 生命周期方法
    public void shutdown()

    // 监控方法
    public int getBannedCount()
    public int getTrackedFingerprintCount()
}
```

### 4.2 配置类

```java
public final class SlowAttackConfig {

    // Builder 入口
    public static Builder builder()

    // Getter 方法
    public long getHeaderTimeout()
    public long getBodyTimeout()
    public long getTotalTimeout()
    public long getBanDuration()
    public int getSlowRequestThreshold()
    public List<String> getWhitelist()
    public boolean isEnableFingerprinting()
    public boolean isIncludeRequestPattern()
    public boolean isNormalizeUri()
    public LogLevel getLogLevel()
}
```

### 4.3 使用示例

```java
// 创建配置
SlowAttackConfig config = SlowAttackConfig.builder()
    .headerTimeout(5000)
    .bodyTimeout(10000)
    .totalTimeout(30000)
    .banDuration(300000)
    .slowRequestThreshold(5)
    .whitelist(Arrays.asList("192.168.1.0/24", "10.0.0.*"))
    .logLevel(LogLevel.DETAILED)
    .build();

// 添加到过滤器链
FilterChainBuilder filterChainBuilder = FilterChainBuilder.stateless();
filterChainBuilder.add(new SlowAttackProtectionFilter(config));
```

---

## 5. 数据结构

### 5.1 攻击类型

```java
public enum AttackType {
    SLOW_HEADER,      // 慢头部攻击
    SLOW_BODY,        // 慢主体攻击
    SLOW_RESPONSE,    // 慢响应攻击
    TOTAL_TIMEOUT     // 总请求超时
}
```

### 5.2 客户端指纹

```java
public final class ClientFingerprint {
    private final String ipAddress;        // IP 地址
    private final String userAgent;        // User-Agent
    private final String requestPattern;   // 请求模式
    private final String simplifiedKey;    // 简化指纹 (IP|UA)
    private final String fullKey;          // 完整指纹 (简化|模式)
}
```

### 5.3 日志级别

```java
public enum LogLevel {
    OFF,        // 关闭日志
    BASIC,      // 基础日志
    DETAILED    // 详细日志
}
```

---

## 6. 依赖关系

### 6.1 Grizzly 内部依赖

| 模块 | 用途 |
|-----|------|
| grizzly-framework | 核心框架，提供 BaseFilter |
| grizzly-http | HTTP 协议支持 |

### 6.2 外部依赖

| 依赖 | 版本 | 用途 |
|-----|------|------|
| JDK | 17+ | 运行环境 |
| JUnit | 4.x | 单元测试 |
| Mockito | 1.9.5 | Mock 测试 |

---

## 7. 验收标准

### 7.1 功能验收

- [x] 支持检测四种慢速攻击类型
- [x] 支持基于指纹的客户端识别
- [x] 支持违规计数和自动封禁
- [x] 支持白名单功能（精确 IP、CIDR、通配符）
- [x] 支持分级日志记录
- [x] 支持灵活的配置

### 7.2 性能验收

- [ ] 性能影响 < 5%
- [ ] 支持 10K+ 并发连接
- [ ] 内存开销可控

### 7.3 质量验收

- [x] 单元测试覆盖率 > 80%
- [x] 集成测试通过
- [x] 代码符合项目规范

---

## 8. 后续优化方向

### 8.1 性能优化

1. 实现更高效的指纹统计结构
2. 优化白名单匹配算法
3. 添加性能指标监控

### 8.2 功能扩展

1. 支持分布式封禁同步
2. 支持自定义检测规则
3. 支持 IPv6 地址处理增强

### 8.3 监控增强

1. 集成 Micrometer 指标导出
2. 添加封禁事件通知机制
3. 支持封禁数据持久化

---

## 9. 变更历史

| 版本 | 日期 | 变更内容 | 作者 |
|-----|------|---------|------|
| 1.0 | 2026-03-03 | 初始版本，基于已实现功能 | System |

---

## 10. 参考资料

- [OWASP Slow HTTP Attack](https://owasp.org/www-community/attacks/Slow_HTTP_Attack)
- Grizzly Framework Documentation
- RFC 2616 - HTTP/1.1
- RFC 7230 - HTTP/1.1 Message Syntax and Routing
