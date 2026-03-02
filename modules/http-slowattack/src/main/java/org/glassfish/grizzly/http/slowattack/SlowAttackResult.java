package org.glassfish.grizzly.http.slowattack;

import java.util.Optional;

/**
 * 慢请求攻击检测结果
 * 用于封装攻击检测的返回信息
 */
public final class SlowAttackResult {

    private final boolean attack;
    private final AttackType attackType;
    private final long elapsedTimeMs;
    private final String details;

    private SlowAttackResult(boolean attack, AttackType attackType, long elapsedTimeMs, String details) {
        this.attack = attack;
        this.attackType = attackType;
        this.elapsedTimeMs = elapsedTimeMs;
        this.details = details;
    }

    /**
     * 创建非攻击结果
     */
    public static SlowAttackResult noAttack() {
        return new SlowAttackResult(false, null, 0L, null);
    }

    /**
     * 创建攻击结果（仅类型和耗时）
     */
    public static SlowAttackResult attack(AttackType attackType, long elapsedTimeMs) {
        return new SlowAttackResult(true, attackType, elapsedTimeMs, null);
    }

    /**
     * 创建攻击结果（包含详细信息）
     */
    public static SlowAttackResult attack(AttackType attackType, long elapsedTimeMs, String details) {
        return new SlowAttackResult(true, attackType, elapsedTimeMs, details);
    }

    /**
     * 是否检测到攻击
     */
    public boolean isAttack() {
        return attack;
    }

    /**
     * 获取攻击类型（如果存在）
     */
    public Optional<AttackType> getAttackType() {
        return Optional.ofNullable(attackType);
    }

    /**
     * 获取耗时（毫秒）
     */
    public long getElapsedTimeMs() {
        return elapsedTimeMs;
    }

    /**
     * 获取详细信息（如果存在）
     */
    public Optional<String> getDetails() {
        return Optional.ofNullable(details);
    }

    @Override
    public String toString() {
        if (attack) {
            return "SlowAttackResult{" +
                    "attack=" + attack +
                    ", attackType=" + attackType +
                    ", elapsedTimeMs=" + elapsedTimeMs +
                    ", details='" + details + '\'' +
                    '}';
        }
        return "SlowAttackResult{no attack}";
    }
}
