package org.glassfish.grizzly.http.slowattack;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IP 白名单管理器
 * 支持精确 IP、CIDR 表示法和通配符匹配
 */
public class WhitelistManager {

    private final Set<String> ipWhitelist;
    private final Set<CidrRange> cidrRanges;
    private final Set<WildcardPattern> wildcardPatterns;

    public WhitelistManager(String[] ipWhitelist) {
        this.ipWhitelist = ConcurrentHashMap.newKeySet();
        this.cidrRanges = ConcurrentHashMap.newKeySet();
        this.wildcardPatterns = ConcurrentHashMap.newKeySet();

        initialize(ipWhitelist);
    }

    private void initialize(String[] ipWhitelist) {
        if (ipWhitelist == null) {
            return;
        }

        for (String entry : ipWhitelist) {
            if (entry == null || entry.trim().isEmpty()) {
                continue;
            }

            entry = entry.trim();

            if (entry.contains("/")) {
                cidrRanges.add(new CidrRange(entry));
            } else if (entry.contains("*")) {
                wildcardPatterns.add(new WildcardPattern(entry));
            } else {
                this.ipWhitelist.add(entry);
            }
        }
    }

    public boolean isWhitelisted(String ip) {
        if (ip == null) {
            return false;
        }

        if (ipWhitelist.contains(ip)) {
            return true;
        }

        for (CidrRange range : cidrRanges) {
            if (range.matches(ip)) {
                return true;
            }
        }

        for (WildcardPattern pattern : wildcardPatterns) {
            if (pattern.matches(ip)) {
                return true;
            }
        }

        return false;
    }

    public void addIp(String ip) {
        if (ip == null || ip.trim().isEmpty()) {
            return;
        }

        ip = ip.trim();

        if (ip.contains("/")) {
            cidrRanges.add(new CidrRange(ip));
        } else if (ip.contains("*")) {
            wildcardPatterns.add(new WildcardPattern(ip));
        } else {
            ipWhitelist.add(ip);
        }
    }

    public void removeIp(String ip) {
        if (ip == null) {
            return;
        }

        ipWhitelist.remove(ip);
    }

    private static class CidrRange {
        private final String baseIp;
        private final int prefixLength;

        CidrRange(String cidr) {
            String[] parts = cidr.split("/");
            this.baseIp = parts[0];
            this.prefixLength = Integer.parseInt(parts[1]);
        }

        boolean matches(String ip) {
            try {
                InetAddress baseAddr = InetAddress.getByName(baseIp);
                InetAddress testAddr = InetAddress.getByName(ip);

                byte[] baseBytes = baseAddr.getAddress();
                byte[] testBytes = testAddr.getAddress();

                if (baseBytes.length != testBytes.length) {
                    return false;
                }

                int bytesToCheck = prefixLength / 8;
                int bitsToCheck = prefixLength % 8;

                for (int i = 0; i < bytesToCheck; i++) {
                    if (baseBytes[i] != testBytes[i]) {
                        return false;
                    }
                }

                if (bitsToCheck > 0 && bytesToCheck < baseBytes.length) {
                    byte mask = (byte) (0xFF << (8 - bitsToCheck));
                    if ((baseBytes[bytesToCheck] & mask) != (testBytes[bytesToCheck] & mask)) {
                        return false;
                    }
                }

                return true;
            } catch (UnknownHostException e) {
                return false;
            }
        }
    }

    private static class WildcardPattern {
        private final String pattern;

        WildcardPattern(String pattern) {
            this.pattern = pattern.replace(".", "\\.");
        }

        boolean matches(String ip) {
            String regex = pattern.replace("*", ".*");
            return ip.matches(regex);
        }
    }
}
