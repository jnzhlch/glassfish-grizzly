package org.glassfish.grizzly.http.slowattack;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * 封禁管理器
 * 管理被封禁的客户端指纹，支持自动过期清理
 */
public class BanManager {

    private static final Logger LOGGER = Logger.getLogger(BanManager.class.getName());

    private final ConcurrentHashMap<String, Long> bannedFingerprints;
    private final long banDuration;
    private final ScheduledExecutorService cleanupExecutor;

    private static final long CLEANUP_INTERVAL_MS = 60000; // 1分钟

    public BanManager(long banDuration) {
        this.bannedFingerprints = new ConcurrentHashMap<>();
        this.banDuration = banDuration;
        this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor(new ThreadFactory() {
            @Override
            public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "SlowAttack-BanCleanup");
                t.setDaemon(true);
                return t;
            }
        });

        startCleanupTask();
    }

    public boolean isBanned(String simplifiedKey) {
        if (simplifiedKey == null) {
            return false;
        }

        Long banTime = bannedFingerprints.get(simplifiedKey);
        if (banTime == null) {
            return false;
        }

        if (System.currentTimeMillis() - banTime > banDuration) {
            bannedFingerprints.remove(simplifiedKey);
            return false;
        }

        return true;
    }

    public void ban(String simplifiedKey) {
        if (simplifiedKey == null || simplifiedKey.isEmpty()) {
            return;
        }

        long now = System.currentTimeMillis();
        bannedFingerprints.put(simplifiedKey, now);

        LOGGER.fine("Fingerprint BANNED - key: " + simplifiedKey + ", duration: " + banDuration + "ms");
    }

    public void unban(String simplifiedKey) {
        if (simplifiedKey == null) {
            return;
        }

        bannedFingerprints.remove(simplifiedKey);
        LOGGER.fine("Fingerprint UNBANNED - key: " + simplifiedKey);
    }

    public void cleanupExpiredBans() {
        long now = System.currentTimeMillis();
        long expireTime = now - banDuration;

        bannedFingerprints.entrySet().removeIf(entry -> {
            if (entry.getValue() < expireTime) {
                LOGGER.fine("Ban expired - key: " + entry.getKey());
                return true;
            }
            return false;
        });
    }

    public int getBannedCount() {
        return bannedFingerprints.size();
    }

    private void startCleanupTask() {
        cleanupExecutor.scheduleAtFixedRate(
            new Runnable() {
                @Override
                public void run() {
                    cleanupExpiredBans();
                }
            },
            CLEANUP_INTERVAL_MS,
            CLEANUP_INTERVAL_MS,
            TimeUnit.MILLISECONDS
        );
    }

    public void shutdown() {
        cleanupExecutor.shutdown();
        try {
            if (!cleanupExecutor.awaitTermination(1, TimeUnit.SECONDS)) {
                cleanupExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            cleanupExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }

        bannedFingerprints.clear();
    }
}
