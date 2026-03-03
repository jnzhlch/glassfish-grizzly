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
