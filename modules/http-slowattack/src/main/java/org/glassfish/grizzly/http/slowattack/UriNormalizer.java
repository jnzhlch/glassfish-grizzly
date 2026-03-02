package org.glassfish.grizzly.http.slowattack;

/**
 * URI 规范化工具类
 * 用于移除 URI 中的动态元素，生成用于指纹匹配的规范化 URI
 */
public final class UriNormalizer {

    private static final String[] SESSION_ID_PATTERNS = {
        ";jsessionid=",
        ";phpsessid=",
        ";sessionid=",
        ";sid="
    };

    private UriNormalizer() {
        // 防止实例化
    }

    /**
     * 规范化 URI
     */
    public static String normalize(String uri) {
        if (uri == null || uri.isEmpty()) {
            return "/";
        }

        String normalized = uri;

        // 移除 query string
        int queryIndex = normalized.indexOf('?');
        if (queryIndex > 0) {
            normalized = normalized.substring(0, queryIndex);
        }

        // 移除 session ID 参数
        normalized = removeSessionIds(normalized);

        // 确保以 / 开头
        if (!normalized.startsWith("/")) {
            normalized = "/" + normalized;
        }

        return normalized;
    }

    /**
     * 移除 URI 中的 session ID
     */
    private static String removeSessionIds(String uri) {
        String lowerUri = uri.toLowerCase();
        int minIndex = Integer.MAX_VALUE;

        // 找到第一个 session ID 的位置
        for (String pattern : SESSION_ID_PATTERNS) {
            int index = lowerUri.indexOf(pattern);
            if (index > 0 && index < minIndex) {
                minIndex = index;
            }
        }

        if (minIndex < Integer.MAX_VALUE) {
            // 找到 session ID 值的结束
            int endIndex = minIndex;
            // 跳过模式本身
            for (String pattern : SESSION_ID_PATTERNS) {
                if (lowerUri.substring(minIndex).startsWith(pattern)) {
                    endIndex = minIndex + pattern.length();
                    break;
                }
            }

            // 找到 session ID 值的结束（下一个 ; 或 ? 或字符串结束）
            while (endIndex < uri.length()) {
                char c = uri.charAt(endIndex);
                if (c == ';' || c == '?' || c == '&') {
                    break;
                }
                endIndex++;
            }

            return uri.substring(0, minIndex) + uri.substring(endIndex);
        }

        return uri;
    }
}
