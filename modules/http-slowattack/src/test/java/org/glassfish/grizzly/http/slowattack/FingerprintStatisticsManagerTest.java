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
