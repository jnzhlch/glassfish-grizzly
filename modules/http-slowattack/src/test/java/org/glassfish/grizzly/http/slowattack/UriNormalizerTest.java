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
