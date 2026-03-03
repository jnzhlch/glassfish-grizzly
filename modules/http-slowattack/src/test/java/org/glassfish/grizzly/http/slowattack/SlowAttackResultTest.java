package org.glassfish.grizzly.http.slowattack;

import org.junit.Test;
import static org.junit.Assert.*;

public class SlowAttackResultTest {

    @Test
    public void testNoAttackResult() {
        SlowAttackResult result = SlowAttackResult.noAttack();
        assertFalse(result.isAttack());
        assertFalse(result.getAttackType().isPresent());
    }

    @Test
    public void testAttackResultWithType() {
        SlowAttackResult result = SlowAttackResult.attack(AttackType.SLOW_HEADER, 5200L);

        assertTrue(result.isAttack());
        assertTrue(result.getAttackType().isPresent());
        assertEquals(AttackType.SLOW_HEADER, result.getAttackType().get());
        assertEquals(5200L, result.getElapsedTimeMs());
    }

    @Test
    public void testAttackResultWithDetails() {
        SlowAttackResult result = SlowAttackResult.attack(
            AttackType.SLOW_BODY,
            10500L,
            "Body chunk interval exceeded"
        );

        assertTrue(result.isAttack());
        assertEquals(AttackType.SLOW_BODY, result.getAttackType().get());
        assertEquals(10500L, result.getElapsedTimeMs());
        assertTrue(result.getDetails().isPresent());
        assertEquals("Body chunk interval exceeded", result.getDetails().get());
    }

    @Test
    public void testNoAttackGetElapsedTime() {
        SlowAttackResult result = SlowAttackResult.noAttack();
        assertEquals(0L, result.getElapsedTimeMs());
    }
}
