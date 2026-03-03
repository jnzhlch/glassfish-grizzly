package org.glassfish.grizzly.http.slowattack;

/**
 * 客户端指纹构建器
 * 根据连接信息构建客户端指纹
 */
public final class FingerprintBuilder {

    private FingerprintBuilder() {
        // 防止实例化
    }

    /**
     * 构建客户端指纹
     *
     * @param ipAddress 客户端 IP 地址
     * @param userAgent User-Agent 字符串
     * @param method HTTP 方法
     * @param uri 请求 URI
     * @return 客户端指纹
     */
    public static ClientFingerprint build(String ipAddress, String userAgent,
                                         String method, String uri) {
        // 规范化 URI
        String normalizedUri = UriNormalizer.normalize(uri);

        // 构建请求模式
        String requestPattern = method + ":" + normalizedUri;

        return new ClientFingerprint(ipAddress, userAgent, requestPattern);
    }
}
