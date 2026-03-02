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
