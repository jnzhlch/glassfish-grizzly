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
