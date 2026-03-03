package org.glassfish.grizzly.http.slowattack;

import org.junit.Test;
import static org.junit.Assert.*;

public class SlowAttackProtectionFilterTest {

    @Test
    public void testFilterInitialization() {
        SlowAttackConfig config = SlowAttackConfig.builder().build();
        SlowAttackProtectionFilter filter = new SlowAttackProtectionFilter(config);
        assertNotNull(filter);
        assertEquals(0, filter.getBannedCount());
        assertEquals(0, filter.getTrackedFingerprintCount());
    }

    @Test
    public void testFilterInitializationWithCustomConfig() {
        SlowAttackConfig config = SlowAttackConfig.builder()
            .headerTimeout(3000)
            .banDuration(600000)
            .slowRequestThreshold(3)
            .build();
        SlowAttackProtectionFilter filter = new SlowAttackProtectionFilter(config);
        assertNotNull(filter);
    }

    @Test
    public void testFilterShutdown() {
        SlowAttackConfig config = SlowAttackConfig.builder().build();
        SlowAttackProtectionFilter filter = new SlowAttackProtectionFilter(config);
        filter.shutdown();
        // After shutdown, should still be accessible
        assertNotNull(filter);
    }
}
