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
