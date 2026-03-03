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
