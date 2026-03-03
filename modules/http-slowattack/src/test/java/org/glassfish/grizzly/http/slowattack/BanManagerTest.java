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
