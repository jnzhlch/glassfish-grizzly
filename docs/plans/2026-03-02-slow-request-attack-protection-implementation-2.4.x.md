# 慢请求攻击防护功能实现计划 (Grizzly 2.4.x)

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**目标:** 为 GlassFish Grizzly HTTP Server (2.4.x) 添加慢请求攻击防护功能，使用指纹追踪（IP + User-Agent + Request Pattern）来识别和封禁恶意客户端。

**架构:** 基于 Grizzly Filter Chain 架构，创建 `SlowAttackProtectionFilter` 继承 `BaseFilter`，拦截在 `ServerCodecFilter` 和 `HttpServerFilter` 之间。使用 ConcurrentHashMap 进行内存存储，ScheduledExecutorService 定期清理过期数据。

**技术栈:** Java 17, Grizzly 2.4.5 NIO Framework, Maven, JUnit 4, Mockito 1.9.5

---

## 版本适配说明

本实现计划基于 Grizzly **2.4.x** 分支（版本 2.4.5-SNAPSHOT），与 main 分支的主要差异：

| 项目 | 2.4.x 版本 | main 分支 |
|------|-----------|----------|
| Java 版本 | 17+ | 21+ |
| JUnit | 4.x | 5.x |
| Mockito | mockito-all 1.9.5 | mockito-core |
| 包名 | org.glassfish.grizzly | org.glassfish.grizzly |
| OSGi | bundle 打包 | bundle 打包 |

---

## 前置条件

### 阅读材料

**必读设计文档:**
- `docs/plans/2026-03-02-slow-request-attack-protection-design.md` - 功能设计文档

**关键源码文件 (2.4.x 分支):**
- `modules/grizzly/src/main/java/org/glassfish/grizzly/filterchain/BaseFilter.java` - 基类
- `modules/grizzly/src/main/java/org/glassfish/grizzly/filterchain/FilterChainContext.java` - 上下文
- `modules/grizzly/src/main/java/org/glassfish/grizzly/attributes/AttributeBuilder.java` - 属性构建器
- `modules/http-server/src/main/java/org/glassfish/grizzly/http/server/HttpServerFilter.java` - 参考

---

## 阶段 1: 模块创建和基础配置

### Task 1: 创建 http-slowattack 模块目录结构

**文件:**
- Create: `modules/http-slowattack/pom.xml`

**Step 1: 创建模块目录**

```bash
mkdir -p modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack
mkdir -p modules/http-slowattack/src/test/java/org/glassfish/grizzly/http/slowattack
```

**Step 2: 创建 pom.xml**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>org.glassfish.grizzly</groupId>
        <artifactId>grizzly-project</artifactId>
        <version>2.4.5-SNAPSHOT</version>
        <relativePath>../../pom.xml</relativePath>
    </parent>

    <artifactId>grizzly-http-slowattack</artifactId>
    <packaging>bundle</packaging>
    <version>2.4.5-SNAPSHOT</version>
    <name>grizzly-http-slowattack</name>

    <build>
        <defaultGoal>install</defaultGoal>
        <resources>
            <resource>
                <filtering>true</filtering>
                <directory>src/main/java/</directory>
                <excludes>
                    <exclude>**/*.java</exclude>
                </excludes>
            </resource>
            <resource>
                <filtering>true</filtering>
                <directory>src/main/resources/</directory>
                <excludes>
                    <exclude>**/*.java</exclude>
                </excludes>
            </resource>
        </resources>
        <plugins>
            <plugin>
                <groupId>org.apache.felix</groupId>
                <artifactId>maven-bundle-plugin</artifactId>
                <version>${felix-version}</version>
                <extensions>true</extensions>
                <configuration>
                    <instructions>
                        <Import-Package>
                            org.glassfish.grizzly*;version=${project.version},
                            *,
                        </Import-Package>
                        <Export-Package>
                            org.glassfish.grizzly.http.slowattack*;version=${project.version},
                        </Export-Package>
                    </instructions>
                </configuration>
            </plugin>
        </plugins>
    </build>

    <dependencies>
        <dependency>
            <groupId>org.glassfish.grizzly</groupId>
            <artifactId>grizzly-http</artifactId>
        </dependency>
        <dependency>
            <groupId>org.glassfish.grizzly</groupId>
            <artifactId>grizzly-http-server</artifactId>
        </dependency>
        <dependency>
            <groupId>org.mockito</groupId>
            <artifactId>mockito-all</artifactId>
            <version>1.9.5</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
```

**Step 3: 更新 modules/pom.xml 添加新模块**

File: `modules/pom.xml`
Location: 在 `<modules>` 部分添加

```xml
<module>http-slowattack</module>
```

**Step 4: 验证模块构建**

```bash
cd modules/http-slowattack && mvn clean compile
```

Expected: BUILD SUCCESS

**Step 5: 提交**

```bash
git add modules/http-slowattack/ modules/pom.xml
git commit -m "feat: create http-slowattack module structure for 2.4.x"
```

---

### Task 2: 创建枚举类型和常量类

**文件:**
- Create: `modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/AttackType.java`
- Create: `modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/LogLevel.java`
- Create: `modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/AttributeKeys.java`

**Step 1: 创建 AttackType 枚举**

```java
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
```

**Step 2: 创建 LogLevel 枚举**

```java
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
```

**Step 3: 创建 AttributeKeys 类**

```java
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
```

**Step 4: 编译验证**

```bash
cd modules/http-slowattack && mvn clean compile
```

Expected: 可能有编译错误（ClientFingerprint 类还未创建）

**Step 5: 提交**

```bash
git add modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/
git commit -m "feat: add AttackType, LogLevel enums and AttributeKeys class"
```

---

## 阶段 2: 核心数据类

### Task 3: 创建 ClientFingerprint 类

**文件:**
- Create: `modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/ClientFingerprint.java`
- Create: `modules/http-slowattack/src/test/java/org/glassfish/grizzly/http/slowattack/ClientFingerprintTest.java`

**Step 1: 编写 JUnit 4 测试用例**

```java
package org.glassfish.grizzly.http.slowattack;

import org.junit.Test;
import static org.junit.Assert.*;

public class ClientFingerprintTest {

    @Test
    public void testFingerprintCreation() {
        ClientFingerprint fp = new ClientFingerprint(
            "192.168.1.50",
            "curl/7.68.0",
            "GET:/api/health"
        );

        assertEquals("192.168.1.50", fp.getIpAddress());
        assertEquals("curl/7.68.0", fp.getUserAgent());
        assertEquals("GET:/api/health", fp.getRequestPattern());
    }

    @Test
    public void testSimplifiedKey() {
        ClientFingerprint fp = new ClientFingerprint(
            "192.168.1.50",
            "curl/7.68.0",
            "GET:/api/health"
        );

        assertEquals("192.168.1.50|curl/7.68.0", fp.getSimplifiedKey());
    }

    @Test
    public void testFullKey() {
        ClientFingerprint fp = new ClientFingerprint(
            "192.168.1.50",
            "curl/7.68.0",
            "GET:/api/health"
        );

        assertEquals("192.168.1.50|curl/7.68.0|GET:/api/health", fp.getFullKey());
    }

    @Test
    public void testEqualsAndHashCode() {
        ClientFingerprint fp1 = new ClientFingerprint(
            "192.168.1.50",
            "curl/7.68.0",
            "GET:/api/health"
        );

        ClientFingerprint fp2 = new ClientFingerprint(
            "192.168.1.50",
            "curl/7.68.0",
            "GET:/api/health"
        );

        assertEquals(fp1, fp2);
        assertEquals(fp1.hashCode(), fp2.hashCode());
    }
}
```

**Step 2: 运行测试确认失败**

```bash
cd modules/http-slowattack && mvn test -Dtest=ClientFingerprintTest
```

Expected: BUILD FAILURE

**Step 3: 创建 ClientFingerprint 类**

```java
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
```

**Step 4: 运行测试确认通过**

```bash
cd modules/http-slowattack && mvn test -Dtest=ClientFingerprintTest
```

Expected: BUILD SUCCESS

**Step 5: 提交**

```bash
git add modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/ClientFingerprint.java
git add modules/http-slowattack/src/test/java/org/glassfish/grizzly/http/slowattack/ClientFingerprintTest.java
git commit -m "feat: add ClientFingerprint data class"
```

---

### Task 4: 创建 SlowAttackResult 类

**文件:**
- Create: `modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/SlowAttackResult.java`
- Create: `modules/http-slowattack/src/test/java/org/glassfish/grizzly/http/slowattack/SlowAttackResultTest.java`

**Step 1: 编写 JUnit 4 测试用例**

```java
package org.glassfish.grizzly.http.slowattack;

import org.junit.Test;
import static org.junit.Assert.*;

public class SlowAttackResultTest {

    @Test
    public void testNoAttackResult() {
        SlowAttackResult result = SlowAttackResult.noAttack();
        assertFalse(result.isAttack());
        assertFalse(result.getAttackType().isPresent());
    }

    @Test
    public void testAttackResultWithType() {
        SlowAttackResult result = SlowAttackResult.attack(AttackType.SLOW_HEADER, 5200L);

        assertTrue(result.isAttack());
        assertTrue(result.getAttackType().isPresent());
        assertEquals(AttackType.SLOW_HEADER, result.getAttackType().get());
        assertEquals(5200L, result.getElapsedTimeMs());
    }

    @Test
    public void testAttackResultWithDetails() {
        SlowAttackResult result = SlowAttackResult.attack(
            AttackType.SLOW_BODY,
            10500L,
            "Body chunk interval exceeded"
        );

        assertTrue(result.isAttack());
        assertEquals(10500L, result.getElapsedTimeMs());
        assertEquals("Body chunk interval exceeded", result.getDetails());
    }
}
```

**Step 2: 运行测试确认失败**

```bash
cd modules/http-slowattack && mvn test -Dtest=SlowAttackResultTest
```

Expected: BUILD FAILURE

**Step 3: 创建 SlowAttackResult 类（包含 Optional 兼容层）**

```java
package org.glassfish.grizzly.http.slowattack;

import java.util.ArrayList;
import java.util.List;

/**
 * 慢请求攻击检测结果
 * 兼容 Java 8，不使用 Optional
 */
public final class SlowAttackResult {

    private final boolean attack;
    private final AttackType attackType;
    private final long elapsedTimeMs;
    private final String details;

    private SlowAttackResult(boolean attack, AttackType attackType, long elapsedTimeMs, String details) {
        this.attack = attack;
        this.attackType = attackType;
        this.elapsedTimeMs = elapsedTimeMs;
        this.details = details;
    }

    /**
     * 创建非攻击结果
     */
    public static SlowAttackResult noAttack() {
        return new SlowAttackResult(false, null, 0, null);
    }

    /**
     * 创建攻击检测结果
     *
     * @param attackType 攻击类型
     * @param elapsedTimeMs 逝去时间（毫秒）
     */
    public static SlowAttackResult attack(AttackType attackType, long elapsedTimeMs) {
        return new SlowAttackResult(true, attackType, elapsedTimeMs, null);
    }

    /**
     * 创建攻击检测结果（带详情）
     *
     * @param attackType 攻击类型
     * @param elapsedTimeMs 逝去时间（毫秒）
     * @param details 详细信息
     */
    public static SlowAttackResult attack(AttackType attackType, long elapsedTimeMs, String details) {
        return new SlowAttackResult(true, attackType, elapsedTimeMs, details);
    }

    /**
     * 是否检测到攻击
     */
    public boolean isAttack() {
        return attack;
    }

    /**
     * 获取攻击类型（Optional 风格）
     * @deprecated 使用 getAttackTypeValue() 代替
     */
    @Deprecated
    public Optional<AttackType> getAttackType() {
        return new Optional<>(attackType);
    }

    /**
     * 获取攻击类型值
     */
    public AttackType getAttackTypeValue() {
        return attackType;
    }

    /**
     * 获取逝去时间（毫秒）
     */
    public long getElapsedTimeMs() {
        return elapsedTimeMs;
    }

    /**
     * 获取详细信息
     */
    public String getDetails() {
        return details;
    }

    @Override
    public String toString() {
        if (!attack) {
            return "SlowAttackResult{no attack}";
        }
        return "SlowAttackResult{" +
                "attack=" + attack +
                ", type=" + attackType +
                ", elapsed=" + elapsedTimeMs + "ms" +
                '}';
    }

    /**
     * 简单的 Optional 兼容类（Java 8）
     */
    public static class Optional<T> {
        private final T value;

        Optional(T value) {
            this.value = value;
        }

        public boolean isPresent() {
            return value != null;
        }

        public T get() {
            if (value == null) {
                throw new IllegalStateException("Value is null");
            }
            return value;
        }
    }
}
```

**Step 4: 修正测试用例**

更新测试用例使用 `getAttackTypeValue()` 而不是 `getAttackType().get()`

**Step 5: 运行测试确认通过**

```bash
cd modules/http-slowattack && mvn test -Dtest=SlowAttackResultTest
```

Expected: BUILD SUCCESS

**Step 6: 提交**

```bash
git add modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/SlowAttackResult.java
git add modules/http-slowattack/src/test/java/org/glassfish/grizzly/http/slowattack/SlowAttackResultTest.java
git commit -m "feat: add SlowAttackResult class"
```

---

## 阶段 3: 工具类和管理器

### Task 5: 创建 UriNormalizer 类

**文件:**
- Create: `modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/UriNormalizer.java`
- Create: `modules/http-slowattack/src/test/java/org/glassfish/grizzly/http/slowattack/UriNormalizerTest.java`

**Step 1: 编写 JUnit 4 测试用例**

```java
package org.glassfish.grizzly.http.slowattack;

import org.junit.Test;
import static org.junit.Assert.*;

public class UriNormalizerTest {

    @Test
    public void testSimplePath() {
        String result = UriNormalizer.normalize("/api/health");
        assertEquals("/api/health", result);
    }

    @Test
    public void testRemoveQueryString() {
        String result = UriNormalizer.normalize("/api/users?id=123&name=test");
        assertEquals("/api/users", result);
    }

    @Test
    public void testRemoveJSessionId() {
        String result = UriNormalizer.normalize("/api/users;jsessionid=ABC123");
        assertEquals("/api/users", result);
    }

    @Test
    public void testNullUri() {
        String result = UriNormalizer.normalize(null);
        assertEquals("/", result);
    }

    @Test
    public void testRootPath() {
        String result = UriNormalizer.normalize("/");
        assertEquals("/", result);
    }
}
```

**Step 2: 运行测试确认失败**

```bash
cd modules/http-slowattack && mvn test -Dtest=UriNormalizerTest
```

Expected: BUILD FAILURE

**Step 3: 创建 UriNormalizer 类**

```java
package org.glassfish.grizzly.http.slowattack;

/**
 * URI 规范化工具类
 * 用于移除 URI 中的动态元素，生成用于指纹匹配的规范化 URI
 */
public final class UriNormalizer {

    private static final String[] SESSION_ID_PATTERNS = {
        ";jsessionid=",
        ";phpsessid=",
        ";sessionid=",
        ";sid="
    };

    private UriNormalizer() {
        // 防止实例化
    }

    /**
     * 规范化 URI
     */
    public static String normalize(String uri) {
        if (uri == null || uri.isEmpty()) {
            return "/";
        }

        String normalized = uri;

        // 移除 query string
        int queryIndex = normalized.indexOf('?');
        if (queryIndex > 0) {
            normalized = normalized.substring(0, queryIndex);
        }

        // 移除 session ID 参数
        normalized = removeSessionIds(normalized);

        // 确保以 / 开头
        if (!normalized.startsWith("/")) {
            normalized = "/" + normalized;
        }

        return normalized;
    }

    /**
     * 移除 URI 中的 session ID
     */
    private static String removeSessionIds(String uri) {
        String lowerUri = uri.toLowerCase();
        int minIndex = Integer.MAX_VALUE;

        // 找到第一个 session ID 的位置
        for (String pattern : SESSION_ID_PATTERNS) {
            int index = lowerUri.indexOf(pattern);
            if (index > 0 && index < minIndex) {
                minIndex = index;
            }
        }

        if (minIndex < Integer.MAX_VALUE) {
            // 找到 session ID 值的结束
            int endIndex = minIndex;
            // 跳过模式本身
            for (String pattern : SESSION_ID_PATTERNS) {
                if (lowerUri.substring(minIndex).startsWith(pattern)) {
                    endIndex = minIndex + pattern.length();
                    break;
                }
            }

            // 找到 session ID 值的结束（下一个 ; 或 ? 或字符串结束）
            while (endIndex < uri.length()) {
                char c = uri.charAt(endIndex);
                if (c == ';' || c == '?' || c == '&') {
                    break;
                }
                endIndex++;
            }

            return uri.substring(0, minIndex) + uri.substring(endIndex);
        }

        return uri;
    }
}
```

**Step 4: 运行测试确认通过**

```bash
cd modules/http-slowattack && mvn test -Dtest=UriNormalizerTest
```

Expected: BUILD SUCCESS

**Step 5: 提交**

```bash
git add modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/UriNormalizer.java
git add modules/http-slowattack/src/test/java/org/glassfish/grizzly/http/slowattack/UriNormalizerTest.java
git commit -m "feat: add UriNormalizer utility class"
```

---

### Task 6: 创建 FingerprintBuilder 类

**文件:**
- Create: `modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/FingerprintBuilder.java`
- Create: `modules/http-slowattack/src/test/java/org/glassfish/grizzly/http/slowattack/FingerprintBuilderTest.java`

**Step 1: 编写 JUnit 4 测试用例**

```java
package org.glassfish.grizzly.http.slowattack;

import org.junit.Test;
import static org.junit.Assert.*;

public class FingerprintBuilderTest {

    @Test
    public void testBuildBasicFingerprint() {
        ClientFingerprint fp = FingerprintBuilder.build(
            "192.168.1.50",
            "curl/7.68.0",
            "GET",
            "/api/health"
        );

        assertEquals("192.168.1.50", fp.getIpAddress());
        assertEquals("curl/7.68.0", fp.getUserAgent());
        assertEquals("GET:/api/health", fp.getRequestPattern());
    }

    @Test
    public void testNormalizeUri() {
        ClientFingerprint fp = FingerprintBuilder.build(
            "192.168.1.50",
            "curl/7.68.0",
            "GET",
            "/api/users?id=123"
        );

        assertEquals("GET:/api/users", fp.getRequestPattern());
    }

    @Test
    public void testNullUserAgent() {
        ClientFingerprint fp = FingerprintBuilder.build(
            "192.168.1.50",
            null,
            "GET",
            "/api/health"
        );

        assertEquals("unknown", fp.getUserAgent());
    }
}
```

**Step 2: 运行测试确认失败**

```bash
cd modules/http-slowattack && mvn test -Dtest=FingerprintBuilderTest
```

Expected: BUILD FAILURE

**Step 3: 创建 FingerprintBuilder 类**

```java
package org.glassfish.grizzly.http.slowattack;

/**
 * 客户端指纹构建器
 * 根据连接信息构建客户端指纹
 */
public final class FingerprintBuilder {

    private FingerprintBuilder() {
        // 防止实例化
    }

    /**
     * 构建客户端指纹
     *
     * @param ipAddress 客户端 IP 地址
     * @param userAgent User-Agent 字符串
     * @param method HTTP 方法
     * @param uri 请求 URI
     * @return 客户端指纹
     */
    public static ClientFingerprint build(String ipAddress, String userAgent,
                                         String method, String uri) {
        // 规范化 URI
        String normalizedUri = UriNormalizer.normalize(uri);

        // 构建请求模式
        String requestPattern = method + ":" + normalizedUri;

        return new ClientFingerprint(ipAddress, userAgent, requestPattern);
    }
}
```

**Step 4: 运行测试确认通过**

```bash
cd modules/http-slowattack && mvn test -Dtest=FingerprintBuilderTest
```

Expected: BUILD SUCCESS

**Step 5: 提交**

```bash
git add modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/FingerprintBuilder.java
git add modules/http-slowattack/src/test/java/org/glassfish/grizzly/http/slowattack/FingerprintBuilderTest.java
git commit -m "feat: add FingerprintBuilder class"
```

---

### Task 7: 创建 WhitelistManager 类

**文件:**
- Create: `modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/WhitelistManager.java`
- Create: `modules/http-slowattack/src/test/java/org/glassfish/grizzly/http/slowattack/WhitelistManagerTest.java`

**Step 1: 编写 JUnit 4 测试用例**

```java
package org.glassfish.grizzly.http.slowattack;

import org.junit.Test;
import static org.junit.Assert.*;

public class WhitelistManagerTest {

    @Test
    public void testExactIpMatch() {
        WhitelistManager manager = new WhitelistManager(new String[]{"192.168.1.50"});
        assertTrue(manager.isWhitelisted("192.168.1.50"));
        assertFalse(manager.isWhitelisted("192.168.1.51"));
    }

    @Test
    public void testCidrNotation() {
        WhitelistManager manager = new WhitelistManager(new String[]{"192.168.1.0/24"});
        assertTrue(manager.isWhitelisted("192.168.1.1"));
        assertTrue(manager.isWhitelisted("192.168.1.255"));
        assertFalse(manager.isWhitelisted("192.168.2.1"));
    }

    @Test
    public void testLocalhost() {
        WhitelistManager manager = new WhitelistManager(new String[]{"127.0.0.1"});
        assertTrue(manager.isWhitelisted("127.0.0.1"));
    }

    @Test
    public void testEmptyWhitelist() {
        WhitelistManager manager = new WhitelistManager(new String[]{});
        assertFalse(manager.isWhitelisted("192.168.1.1"));
    }
}
```

**Step 2: 运行测试确认失败**

```bash
cd modules/http-slowattack && mvn test -Dtest=WhitelistManagerTest
```

Expected: BUILD FAILURE

**Step 3: 创建 WhitelistManager 类**

```java
package org.glassfish.grizzly.http.slowattack;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IP 白名单管理器
 * 支持精确 IP、CIDR 表示法和通配符匹配
 */
public class WhitelistManager {

    private final Set<String> ipWhitelist;
    private final Set<CidrRange> cidrRanges;
    private final Set<WildcardPattern> wildcardPatterns;

    public WhitelistManager(String[] ipWhitelist) {
        this.ipWhitelist = ConcurrentHashMap.newKeySet();
        this.cidrRanges = ConcurrentHashMap.newKeySet();
        this.wildcardPatterns = ConcurrentHashMap.newKeySet();

        initialize(ipWhitelist);
    }

    private void initialize(String[] ipWhitelist) {
        if (ipWhitelist == null) {
            return;
        }

        for (String entry : ipWhitelist) {
            if (entry == null || entry.trim().isEmpty()) {
                continue;
            }

            entry = entry.trim();

            if (entry.contains("/")) {
                cidrRanges.add(new CidrRange(entry));
            } else if (entry.contains("*")) {
                wildcardPatterns.add(new WildcardPattern(entry));
            } else {
                this.ipWhitelist.add(entry);
            }
        }
    }

    public boolean isWhitelisted(String ip) {
        if (ip == null) {
            return false;
        }

        if (ipWhitelist.contains(ip)) {
            return true;
        }

        for (CidrRange range : cidrRanges) {
            if (range.matches(ip)) {
                return true;
            }
        }

        for (WildcardPattern pattern : wildcardPatterns) {
            if (pattern.matches(ip)) {
                return true;
            }
        }

        return false;
    }

    public void addIp(String ip) {
        if (ip == null || ip.trim().isEmpty()) {
            return;
        }

        ip = ip.trim();

        if (ip.contains("/")) {
            cidrRanges.add(new CidrRange(ip));
        } else if (ip.contains("*")) {
            wildcardPatterns.add(new WildcardPattern(ip));
        } else {
            ipWhitelist.add(ip);
        }
    }

    public void removeIp(String ip) {
        if (ip == null) {
            return;
        }

        ipWhitelist.remove(ip);
    }

    private static class CidrRange {
        private final String baseIp;
        private final int prefixLength;

        CidrRange(String cidr) {
            String[] parts = cidr.split("/");
            this.baseIp = parts[0];
            this.prefixLength = Integer.parseInt(parts[1]);
        }

        boolean matches(String ip) {
            try {
                InetAddress baseAddr = InetAddress.getByName(baseIp);
                InetAddress testAddr = InetAddress.getByName(ip);

                byte[] baseBytes = baseAddr.getAddress();
                byte[] testBytes = testAddr.getAddress();

                if (baseBytes.length != testBytes.length) {
                    return false;
                }

                int bytesToCheck = prefixLength / 8;
                int bitsToCheck = prefixLength % 8;

                for (int i = 0; i < bytesToCheck; i++) {
                    if (baseBytes[i] != testBytes[i]) {
                        return false;
                    }
                }

                if (bitsToCheck > 0 && bytesToCheck < baseBytes.length) {
                    byte mask = (byte) (0xFF << (8 - bitsToCheck));
                    if ((baseBytes[bytesToCheck] & mask) != (testBytes[bytesToCheck] & mask)) {
                        return false;
                    }
                }

                return true;
            } catch (UnknownHostException e) {
                return false;
            }
        }
    }

    private static class WildcardPattern {
        private final String pattern;

        WildcardPattern(String pattern) {
            this.pattern = pattern.replace(".", "\\.");
        }

        boolean matches(String ip) {
            String regex = pattern.replace("*", ".*");
            return ip.matches(regex);
        }
    }
}
```

**Step 4: 运行测试确认通过**

```bash
cd modules/http-slowattack && mvn test -Dtest=WhitelistManagerTest
```

Expected: BUILD SUCCESS

**Step 5: 提交**

```bash
git add modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/WhitelistManager.java
git add modules/http-slowattack/src/test/java/org/glassfish/grizzly/http/slowattack/WhitelistManagerTest.java
git commit -m "feat: add WhitelistManager class"
```

---

### Task 8: 创建 BanManager 类

**文件:**
- Create: `modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/BanManager.java`
- Create: `modules/http-slowattack/src/test/java/org/glassfish/grizzly/http/slowattack/BanManagerTest.java`

**Step 1: 编写 JUnit 4 测试用例**

```java
package org.glassfish.grizzly.http.slowattack;

import org.junit.After;
import org.junit.Test;
import static org.junit.Assert.*;

public class BanManagerTest {

    private BanManager banManager;

    @After
    public void tearDown() {
        if (banManager != null) {
            banManager.shutdown();
        }
    }

    @Test
    public void testIsBannedInitiallyFalse() {
        banManager = new BanManager(300000);
        String key = "192.168.1.50|curl/7.68.0";
        assertFalse(banManager.isBanned(key));
    }

    @Test
    public void testBanAndIsBanned() {
        banManager = new BanManager(300000);
        String key = "192.168.1.50|curl/7.68.0";

        banManager.ban(key);
        assertTrue(banManager.isBanned(key));
    }

    @Test
    public void testUnban() {
        banManager = new BanManager(300000);
        String key = "192.168.1.50|curl/7.68.0";

        banManager.ban(key);
        assertTrue(banManager.isBanned(key));

        banManager.unban(key);
        assertFalse(banManager.isBanned(key));
    }

    @Test
    public void testGetBannedCount() {
        banManager = new BanManager(300000);

        assertEquals(0, banManager.getBannedCount());

        banManager.ban("192.168.1.50|curl/7.68.0");
        banManager.ban("10.0.0.1|Mozilla/5.0");

        assertEquals(2, banManager.getBannedCount());
    }

    @Test
    public void testCleanupExpiredBans() throws InterruptedException {
        banManager = new BanManager(50);

        banManager.ban("192.168.1.50|curl/7.68.0");
        assertEquals(1, banManager.getBannedCount());

        Thread.sleep(100);
        banManager.cleanupExpiredBans();

        assertEquals(0, banManager.getBannedCount());
    }
}
```

**Step 2: 运行测试确认失败**

```bash
cd modules/http-slowattack && mvn test -Dtest=BanManagerTest
```

Expected: BUILD FAILURE

**Step 3: 创建 BanManager 类**

```java
package org.glassfish.grizzly.http.slowattack;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * 封禁管理器
 * 管理被封禁的客户端指纹，支持自动过期清理
 */
public class BanManager {

    private static final Logger LOGGER = Logger.getLogger(BanManager.class.getName());

    private final ConcurrentHashMap<String, Long> bannedFingerprints;
    private final long banDuration;
    private final ScheduledExecutorService cleanupExecutor;

    private static final long CLEANUP_INTERVAL_MS = 60000; // 1分钟

    public BanManager(long banDuration) {
        this.bannedFingerprints = new ConcurrentHashMap<>();
        this.banDuration = banDuration;
        this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "SlowAttack-BanCleanup");
                t.setDaemon(true);
                return t;
            }
        });

        startCleanupTask();
    }

    public boolean isBanned(String simplifiedKey) {
        if (simplifiedKey == null) {
            return false;
        }

        Long banTime = bannedFingerprints.get(simplifiedKey);
        if (banTime == null) {
            return false;
        }

        if (System.currentTimeMillis() - banTime > banDuration) {
            bannedFingerprints.remove(simplifiedKey);
            return false;
        }

        return true;
    }

    public void ban(String simplifiedKey) {
        if (simplifiedKey == null || simplifiedKey.isEmpty()) {
            return;
        }

        long now = System.currentTimeMillis();
        bannedFingerprints.put(simplifiedKey, now);

        LOGGER.fine("Fingerprint BANNED - key: " + simplifiedKey + ", duration: " + banDuration + "ms");
    }

    public void unban(String simplifiedKey) {
        if (simplifiedKey == null) {
            return;
        }

        bannedFingerprints.remove(simplifiedKey);
        LOGGER.fine("Fingerprint UNBANNED - key: " + simplifiedKey);
    }

    public void cleanupExpiredBans() {
        long now = System.currentTimeMillis();
        long expireTime = now - banDuration;

        bannedFingerprints.entrySet().removeIf(entry -> {
            if (entry.getValue() < expireTime) {
                LOGGER.fine("Ban expired - key: " + entry.getKey());
                return true;
            }
            return false;
        });
    }

    public int getBannedCount() {
        return bannedFingerprints.size();
    }

    private void startCleanupTask() {
        cleanupExecutor.scheduleAtFixedRate(
            new Runnable() {
                @Override
                public void run() {
                    cleanupExpiredBans();
                }
            },
            CLEANUP_INTERVAL_MS,
            CLEANUP_INTERVAL_MS,
            TimeUnit.MILLISECONDS
        );
    }

    public void shutdown() {
        cleanupExecutor.shutdown();
        try {
            if (!cleanupExecutor.awaitTermination(1, TimeUnit.SECONDS)) {
                cleanupExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            cleanupExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }

        bannedFingerprints.clear();
    }
}
```

**Step 4: 运行测试确认通过**

```bash
cd modules/http-slowattack && mvn test -Dtest=BanManagerTest
```

Expected: BUILD SUCCESS

**Step 5: 提交**

```bash
git add modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/BanManager.java
git add modules/http-slowattack/src/test/java/org/glassfish/grizzly/http/slowattack/BanManagerTest.java
git commit -m "feat: add BanManager class"
```

---

### Task 9: 创建 FingerprintStatisticsManager 类

**文件:**
- Create: `modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/FingerprintStatisticsManager.java`
- Create: `modules/http-slowattack/src/test/java/org/glassfish/grizzly/http/slowattack/FingerprintStatisticsManagerTest.java`

**Step 1: 编写 JUnit 4 测试用例**

```java
package org.glassfish.grizzly.http.slowattack;

import org.junit.Test;
import static org.junit.Assert.*;

public class FingerprintStatisticsManagerTest {

    @Test
    public void testInitialViolationCount() {
        FingerprintStatisticsManager manager = new FingerprintStatisticsManager();
        ClientFingerprint fp = new ClientFingerprint("192.168.1.50", "curl/7.68.0", "GET:/api/health");

        assertEquals(0, manager.getViolationCount(fp));
    }

    @Test
    public void testRecordViolation() {
        FingerprintStatisticsManager manager = new FingerprintStatisticsManager();
        ClientFingerprint fp = new ClientFingerprint("192.168.1.50", "curl/7.68.0", "GET:/api/health");

        manager.recordViolation(fp);
        assertEquals(1, manager.getViolationCount(fp));

        manager.recordViolation(fp);
        assertEquals(2, manager.getViolationCount(fp));
    }

    @Test
    public void testClearStatistics() {
        FingerprintStatisticsManager manager = new FingerprintStatisticsManager();
        ClientFingerprint fp = new ClientFingerprint("192.168.1.50", "curl/7.68.0", "GET:/api/health");

        manager.recordViolation(fp);
        manager.recordViolation(fp);
        assertEquals(2, manager.getViolationCount(fp));

        manager.clearStatistics(fp);
        assertEquals(0, manager.getViolationCount(fp));
    }

    @Test
    public void testRequestTimeTracking() throws InterruptedException {
        FingerprintStatisticsManager manager = new FingerprintStatisticsManager();
        String key = "192.168.1.50|curl/7.68.0|GET:/api/health";

        manager.recordRequestStart(key);

        Thread.sleep(100);

        assertTrue(manager.isTotalRequestTimeout(key, 50));
        assertFalse(manager.isTotalRequestTimeout(key, 200));
    }

    @Test
    public void testIsolatedFingerprints() {
        FingerprintStatisticsManager manager = new FingerprintStatisticsManager();

        ClientFingerprint fp1 = new ClientFingerprint("192.168.1.50", "curl/7.68.0", "GET:/api/health");
        ClientFingerprint fp2 = new ClientFingerprint("192.168.1.50", "curl/7.68.0", "POST:/api/data");

        manager.recordViolation(fp1);
        manager.recordViolation(fp2);

        assertEquals(1, manager.getViolationCount(fp1));
        assertEquals(1, manager.getViolationCount(fp2));
    }
}
```

**Step 2: 运行测试确认失败**

```bash
cd modules/http-slowattack && mvn test -Dtest=FingerprintStatisticsManagerTest
```

Expected: BUILD FAILURE

**Step 3: 创建 FingerprintStatisticsManager 类**

```java
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
        violationCounts.computeIfAbsent(key, new ConcurrentHashMap.Functor<String, AtomicInteger>() {
            @Override
            public AtomicInteger apply(String key) {
                return new AtomicInteger(0);
            }
        }).incrementAndGet();
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
```

**注意**: 2.4.x 版本可能不支持 `computeIfAbsent` 的 lambda 表达式，需要使用匿名类或替代方法。

**Step 4: 修正兼容性问题**

```java
violationCounts.computeIfAbsent(key, new ConcurrentHashMap.Functor<String, AtomicInteger>() {
    @Override
    public AtomicInteger apply(String key) {
        return new AtomicInteger(0);
    }
}).incrementAndGet();
```

或者使用更简单的方式：

```java
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
```

**Step 5: 运行测试确认通过**

```bash
cd modules/http-slowattack && mvn test -Dtest=FingerprintStatisticsManagerTest
```

Expected: BUILD SUCCESS

**Step 6: 提交**

```bash
git add modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/FingerprintStatisticsManager.java
git add modules/http-slowattack/src/test/java/org/glassfish/grizzly/http/slowattack/FingerprintStatisticsManagerTest.java
git commit -m "feat: add FingerprintStatisticsManager class"
```

---

### Task 10: 创建 SlowAttackConfig 配置类

**文件:**
- Create: `modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/SlowAttackConfig.java`
- Create: `modules/http-slowattack/src/test/java/org/glassfish/grizzly/http/slowattack/SlowAttackConfigTest.java`

**Step 1: 编写 JUnit 4 测试用例**

```java
package org.glassfish.grizzly.http.slowattack;

import org.junit.Test;
import static org.junit.Assert.*;

import java.util.Arrays;

public class SlowAttackConfigTest {

    @Test
    public void testDefaultConfig() {
        SlowAttackConfig config = SlowAttackConfig.builder().build();

        assertEquals(5000, config.getHeaderTimeout());
        assertEquals(10000, config.getBodyTimeout());
        assertEquals(30000, config.getTotalTimeout());
        assertEquals(300000, config.getBanDuration());
        assertEquals(5, config.getSlowRequestThreshold());
        assertTrue(config.getWhitelist().isEmpty());
        assertTrue(config.isEnableFingerprinting());
        assertEquals(LogLevel.DETAILED, config.getLogLevel());
    }

    @Test
    public void testCustomConfig() {
        SlowAttackConfig config = SlowAttackConfig.builder()
            .headerTimeout(3000)
            .bodyTimeout(15000)
            .banDuration(600000)
            .slowRequestThreshold(3)
            .whitelist(Arrays.asList("127.0.0.1", "192.168.1.0/24"))
            .logLevel(LogLevel.BASIC)
            .build();

        assertEquals(3000, config.getHeaderTimeout());
        assertEquals(15000, config.getBodyTimeout());
        assertEquals(600000, config.getBanDuration());
        assertEquals(3, config.getSlowRequestThreshold());
        assertEquals(2, config.getWhitelist().size());
        assertEquals(LogLevel.BASIC, config.getLogLevel());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidHeaderTimeout() {
        SlowAttackConfig.builder().headerTimeout(-1).build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidBanDuration() {
        SlowAttackConfig.builder().banDuration(0).build();
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalidThreshold() {
        SlowAttackConfig.builder().slowRequestThreshold(0).build();
    }
}
```

**Step 2: 运行测试确认失败**

```bash
cd modules/http-slowattack && mvn test -Dtest=SlowAttackConfigTest
```

Expected: BUILD FAILURE

**Step 3: 创建 SlowAttackConfig 类**

```java
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
```

**Step 4: 运行测试确认通过**

```bash
cd modules/http-slowattack && mvn test -Dtest=SlowAttackConfigTest
```

Expected: BUILD SUCCESS

**Step 5: 提交**

```bash
git add modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/SlowAttackConfig.java
git add modules/http-slowattack/src/test/java/org/glassfish/grizzly/http/slowattack/SlowAttackConfigTest.java
git commit -m "feat: add SlowAttackConfig class"
```

---

## 阶段 4: 核心过滤器实现

### Task 11: 创建 DetailedEventLogger 类

**文件:**
- Create: `modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/DetailedEventLogger.java`
- Create: `modules/http-slowattack/src/test/java/org/glassfish/grizzly/http/slowattack/DetailedEventLoggerTest.java`

**Step 1: 编写 JUnit 4 测试用例**

```java
package org.glassfish.grizzly.http.slowattack;

import org.junit.Test;
import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

public class DetailedEventLoggerTest {

    @Test
    public void testLogSlowHeaderDetected() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        DetailedEventLogger logger = new DetailedEventLogger(LogLevel.DETAILED, new PrintStream(out));

        ClientFingerprint fp = new ClientFingerprint("192.168.1.50", "curl/7.68.0", "GET:/api/health");
        logger.logSlowHeaderDetected(fp, 5200);

        String output = out.toString();
        assertTrue(output.contains("Slow header detected"));
        assertTrue(output.contains("192.168.1.50"));
        assertTrue(output.contains("5200"));
    }

    @Test
    public void testLogLevelOff() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        DetailedEventLogger logger = new DetailedEventLogger(LogLevel.OFF, new PrintStream(out));

        ClientFingerprint fp = new ClientFingerprint("192.168.1.50", "curl/7.68.0", "GET:/api/health");
        logger.logSlowHeaderDetected(fp, 5200);

        String output = out.toString();
        assertTrue(output.isEmpty());
    }

    @Test
    public void testLogLevelBasic() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        DetailedEventLogger logger = new DetailedEventLogger(LogLevel.BASIC, new PrintStream(out));

        ClientFingerprint fp = new ClientFingerprint("192.168.1.50", "curl/7.68.0", "GET:/api/health");
        logger.logSlowHeaderDetected(fp, 5200);

        String output = out.toString();
        assertFalse(output.isEmpty());
    }
}
```

**Step 2: 运行测试确认失败**

```bash
cd modules/http-slowattack && mvn test -Dtest=DetailedEventLoggerTest
```

Expected: BUILD FAILURE

**Step 3: 创建 DetailedEventLogger 类**

```java
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
```

**Step 4: 运行测试确认通过**

```bash
cd modules/http-slowattack && mvn test -Dtest=DetailedEventLoggerTest
```

Expected: BUILD SUCCESS

**Step 5: 提交**

```bash
git add modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/DetailedEventLogger.java
git add modules/http-slowattack/src/test/java/org/glassfish/grizzly/http/slowattack/DetailedEventLoggerTest.java
git commit -m "feat: add DetailedEventLogger class"
```

---

### Task 12: 创建 SlowAttackProtectionFilter 核心过滤器

**文件:**
- Create: `modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/SlowAttackProtectionFilter.java`
- Create: `modules/http-slowattack/src/test/java/org/glassfish/grizzly/http/slowattack/SlowAttackProtectionFilterTest.java`

**Step 1: 编写基础测试用例**

```java
package org.glassfish.grizzly.http.slowattack;

import org.glassfish.grizzly.Connection;
import org.glassfish.grizzly.filterchain.FilterChainContext;
import org.glassfish.grizzly.filterchain.NextAction;
import org.glassfish.grizzly.http.HttpContent;
import org.glassfish.grizzly.http.HttpRequestPacket;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class SlowAttackProtectionFilterTest {

    @Mock
    private FilterChainContext ctx;

    @Mock
    private Connection connection;

    @Mock
    private HttpRequestPacket requestPacket;

    @Mock
    private HttpContent httpContent;

    private SlowAttackProtectionFilter filter;
    private SlowAttackConfig config;

    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
        config = SlowAttackConfig.builder().build();
        filter = new SlowAttackProtectionFilter(config);

        when(ctx.getConnection()).thenReturn(connection);
        when(ctx.getMessage()).thenReturn(httpContent);
        when(httpContent.getHttpHeader()).thenReturn(requestPacket);
    }

    @Test
    public void testWhitelistedIpPassesThrough() throws Exception {
        config = SlowAttackConfig.builder()
            .whitelist(java.util.Arrays.asList("192.168.1.50"))
            .build();
        filter = new SlowAttackProtectionFilter(config);

        when(requestPacket.getRemoteAddress()).thenReturn("192.168.1.50");

        NextAction action = filter.handleRead(ctx);

        verify(ctx, never()).getStopAction();
        assertNotNull(action);
    }

    @Test
    public void testFilterInitialization() {
        assertNotNull(filter);
    }
}
```

**Step 2: 运行测试确认失败**

```bash
cd modules/http-slowattack && mvn test -Dtest=SlowAttackProtectionFilterTest
```

Expected: BUILD FAILURE

**Step 3: 创建 SlowAttackProtectionFilter 类（核心实现）**

```java
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
```

**Step 4: 运行测试并修复**

```bash
cd modules/http-slowattack && mvn test -Dtest=SlowAttackProtectionFilterTest
```

Expected: 可能需要 Mock 调整

**Step 5: 提交**

```bash
git add modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/SlowAttackProtectionFilter.java
git add modules/http-slowattack/src/test/java/org/glassfish/grizzly/http/slowattack/SlowAttackProtectionFilterTest.java
git commit -m "feat: add SlowAttackProtectionFilter core filter"
```

---

## 阶段 5: 集成和测试

### Task 13: 创建集成测试

**文件:**
- Create: `modules/http-slowattack/src/test/java/org/glassfish/grizzly/http/slowattack/SlowAttackProtectionIntegrationTest.java`

**Step 1: 编写集成测试**

```java
package org.glassfish.grizzly.http.slowattack;

import org.glassfish.grizzly.http.server.HttpHandler;
import org.glassfish.grizzly.http.server.HttpServer;
import org.glassfish.grizzly.http.server.NetworkListener;
import org.glassfish.grizzly.http.server.Request;
import org.glassfish.grizzly.http.server.Response;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

import static org.junit.Assert.*;

public class SlowAttackProtectionIntegrationTest {

    private HttpServer server;
    private int port = 18080;

    @Before
    public void setUp() throws Exception {
        server = createTestServer(port);
        server.start();
        Thread.sleep(500); // 等待服务器启动
    }

    @After
    public void tearDown() {
        if (server != null) {
            server.shutdownNow();
        }
    }

    @Test
    public void testNormalRequestPasses() throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL("http://localhost:" + port + "/test").openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(5000);

        assertEquals(200, conn.getResponseCode());
    }

    @Test
    public void testWhitelistedIpAlwaysPasses() throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL("http://localhost:" + port + "/test").openConnection();
        assertEquals(200, conn.getResponseCode());
    }

    private HttpServer createTestServer(int port) {
        HttpServer server = new HttpServer();
        NetworkListener listener = new NetworkListener("grizzly", "localhost", port);
        server.addListener(listener);

        SlowAttackConfig config = SlowAttackConfig.builder()
            .headerTimeout(3000)
            .bodyTimeout(5000)
            .totalTimeout(10000)
            .slowRequestThreshold(3)
            .banDuration(5000)
            .whitelist(java.util.Arrays.asList("127.0.0.1", "::1", "localhost"))
            .logLevel(LogLevel.DETAILED)
            .build();

        SlowAttackProtectionFilter filter = new SlowAttackProtectionFilter(config);
        listener.getFilterChain().add(filter);

        server.getServerConfiguration().addHttpHandler(new HttpHandler() {
            @Override
            public void service(Request request, Response response) throws Exception {
                response.setStatus(200);
                response.setContentType("text/plain");
                response.getWriter().write("OK");
            }
        }, "/test");

        return server;
    }
}
```

**Step 2: 运行集成测试**

```bash
cd modules/http-slowattack && mvn test -Dtest=SlowAttackProtectionIntegrationTest
```

Expected: 可能需要端口处理和服务器启动调整

**Step 3: 提交**

```bash
git add modules/http-slowattack/src/test/java/org/glassfish/grizzly/http/slowattack/SlowAttackProtectionIntegrationTest.java
git commit -m "test: add integration tests"
```

---

### Task 14: 创建使用示例和文档

**文件:**
- Create: `modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/example/SlowAttackExample.java`

**Step 1: 创建使用示例**

```java
package org.glassfish.grizzly.http.slowattack.example;

import org.glassfish.grizzly.http.server.HttpHandler;
import org.glassfish.grizzly.http.server.HttpServer;
import org.glassfish.grizzly.http.server.NetworkListener;
import org.glassfish.grizzly.http.server.Request;
import org.glassfish.grizzly.http.server.Response;
import org.glassfish.grizzly.http.slowattack.SlowAttackConfig;
import org.glassfish.grizzly.http.slowattack.SlowAttackProtectionFilter;
import org.glassfish.grizzly.http.slowattack.LogLevel;

import java.io.IOException;

/**
 * 慢请求攻击防护使用示例 (Grizzly 2.4.x)
 */
public class SlowAttackExample {

    public static void main(String[] args) throws IOException {
        HttpServer server = new HttpServer();
        NetworkListener listener = new NetworkListener("grizzly", "localhost", 8080);
        server.addListener(listener);

        SlowAttackConfig config = SlowAttackConfig.builder()
            .headerTimeout(5000)
            .bodyTimeout(10000)
            .totalTimeout(30000)
            .banDuration(300000)
            .slowRequestThreshold(5)
            .whitelist(java.util.Arrays.asList(
                "127.0.0.1",
                "192.168.1.0/24",
                "10.0.*"
            ))
            .enableFingerprinting(true)
            .includeRequestPattern(true)
            .normalizeUri(true)
            .logLevel(LogLevel.DETAILED)
            .build();

        SlowAttackProtectionFilter filter = new SlowAttackProtectionFilter(config);
        listener.getFilterChain().add(filter);

        server.getServerConfiguration().addHttpHandler(new HttpHandler() {
            @Override
            public void service(Request request, Response response) throws Exception {
                response.setContentType("text/plain");
                response.getWriter().write("Hello, Grizzly 2.4.x with Slow Attack Protection!");
            }
        }, "/");

        server.start();
        System.out.println("Server started on http://localhost:8080");
        System.out.println("Slow attack protection enabled with fingerprint tracking");
        System.out.println("Press any key to stop...");
        System.in.read();

        server.shutdownNow();
    }
}
```

**Step 2: 提交**

```bash
git add modules/http-slowattack/src/main/java/org/glassfish/grizzly/http/slowattack/example/SlowAttackExample.java
git commit -m "docs: add usage example for 2.4.x"
```

---

### Task 15: 运行完整测试套件并验证

**Step 1: 运行所有测试**

```bash
cd modules/http-slowattack && mvn clean test
```

Expected: 所有测试通过

**Step 2: 验证模块编译和打包**

```bash
cd modules/http-slowattack && mvn clean install
```

Expected: BUILD SUCCESS，生成 JAR 文件

**Step 3: 检查生成的 JAR 内容**

```bash
jar -tf modules/http-slowattack/target/grizzly-http-slowattack-*.jar | head -20
```

Expected: 列出编译后的 class 文件

**Step 4: 提交最终版本**

```bash
git add -A
git commit -m "feat: complete slow request attack protection implementation for 2.4.x

Add fingerprint-based slow request attack protection for Grizzly 2.4.x HTTP Server.

Features:
- Protection against Slow Headers, Slow POST, and Slow Read attacks
- Client fingerprinting (IP + User-Agent + Request Pattern)
- IP whitelist with CIDR and wildcard support
- Configurable timeouts and ban thresholds
- Detailed event logging

Components:
- SlowAttackProtectionFilter: Core filter for attack detection
- BanManager: Manages banned clients with auto-cleanup
- WhitelistManager: IP whitelist management
- FingerprintStatisticsManager: Tracks violations per fingerprint
- UriNormalizer: URI normalization for fingerprint matching
- ClientFingerprint: Immutable fingerprint data class
- SlowAttackConfig: Builder-based configuration

Tests:
- Unit tests for all components (JUnit 4)
- Integration tests for end-to-end scenarios
- Concurrent access safety tests

Compatibility:
- Java 17+
- Grizzly 2.4.x (2.4.5-SNAPSHOT)
- JUnit 4
- Mockito 1.9.5"
```

---

## 实现完成检查清单

- [ ] 所有类都已创建并编译通过
- [ ] 所有单元测试通过 (JUnit 4)
- [ ] 集成测试通过
- [ ] 模块可以成功构建和打包
- [ ] 使用示例可以正常运行
- [ ] 代码已提交到 git (2.4.x 分支)

---

## 2.4.x 版本特别注意事项

1. **Java 版本**: 使用 Java 17+ 语法特性（避免 Java 21 特性）
2. **测试框架**: 使用 JUnit 4 而非 JUnit 5
3. **Mockito**: 使用 mockito-all 1.9.5 而非 mockito-core
4. **Optional兼容**: 由于 Java 8 兼容性，使用简单的 Optional 包装而非 java.util.Optional
5. **Lambda表达式**: 谨慎使用 lambda 表达式，部分场景使用匿名类
6. **ThreadFactory**: 使用显式 ThreadFactory 接口实现

---

## 后续工作

1. **性能测试**: 验证防护功能对正常请求的性能影响 < 5%
2. **压力测试**: 测试高并发场景下的内存使用和稳定性
3. **更多测试用例**: 添加边界条件和异常场景测试
4. **文档完善**: 补充 API 文档和更多使用示例
