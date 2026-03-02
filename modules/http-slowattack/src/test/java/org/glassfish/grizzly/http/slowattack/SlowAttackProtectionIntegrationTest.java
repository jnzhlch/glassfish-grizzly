package org.glassfish.grizzly.http.slowattack;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 * 慢请求攻击防护集成测试
 * 注意：完整的集成测试需要实际 HTTP 服务器环境
 * 此测试作为框架，可在实际环境中运行
 */
public class SlowAttackProtectionIntegrationTest {

    @Test
    public void testIntegrationFramework() {
        // 基本集成测试框架
        // 完整的 HTTP 服务器集成测试需要更复杂的环境设置
        // 这里的测试确保模块可以正常加载和初始化

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

        assertNotNull(filter);
        assertEquals(0, filter.getBannedCount());

        filter.shutdown();
    }
}
