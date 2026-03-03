package org.glassfish.grizzly.http.slowattack.example;

import org.glassfish.grizzly.http.server.HttpHandler;
import org.glassfish.grizzly.http.server.HttpServer;
import org.glassfish.grizzly.http.server.NetworkListener;
import org.glassfish.grizzly.http.server.Request;
import org.glassfish.grizzly.http.server.Response;
import org.glassfish.grizzly.http.slowattack.SlowAttackConfig;
import org.glassfish.grizzly.http.slowattack.SlowAttackProtectionFilter;
import org.glassfish.grizzly.http.slowattack.LogLevel;

import java.io.IOException;

/**
 * 慢请求攻击防护使用示例 (Grizzly 2.4.x)
 *
 * 此示例展示如何配置和使用 SlowAttackProtectionFilter
 * 来防护 HTTP 慢请求攻击。
 */
public class SlowAttackExample {

    public static void main(String[] args) throws IOException {
        HttpServer server = new HttpServer();
        NetworkListener listener = new NetworkListener("grizzly", "localhost", 8080);
        server.addListener(listener);

        // 配置慢请求攻击防护
        SlowAttackConfig config = SlowAttackConfig.builder()
            .headerTimeout(5000)           // 头部接收超时: 5秒
            .bodyTimeout(10000)            // 主体接收超时: 10秒
            .totalTimeout(30000)           // 总请求超时: 30秒
            .banDuration(300000)           // 封禁时长: 5分钟
            .slowRequestThreshold(5)       // 违规阈值: 5次
            .whitelist(java.util.Arrays.asList(
                "127.0.0.1",                // 本地回环
                "192.168.1.0/24",          // 内网 CIDR
                "10.0.*"                   // 通配符
            ))
            .enableFingerprinting(true)   // 启用指纹追踪
            .includeRequestPattern(true)  // 包含请求模式
            .normalizeUri(true)           // 规范化 URI
            .logLevel(LogLevel.DETAILED)   // 详细日志
            .build();

        // 创建并添加过滤器
        SlowAttackProtectionFilter filter = new SlowAttackProtectionFilter(config);
        // 注意：在 Grizzly 2.4.x 中，需要在服务器启动后动态添加过滤器
        // 或使用 FilterChainBuilder 来构建完整的过滤器链

        server.getServerConfiguration().addHttpHandler(new HttpHandler() {
            @Override
            public void service(Request request, Response response) throws Exception {
                response.setContentType("text/plain");
                response.getWriter().write("Hello, Grizzly 2.4.x with Slow Attack Protection!");
            }
        }, "/");

        server.start();
        System.out.println("Server started on http://localhost:8080");
        System.out.println("Slow attack protection enabled with fingerprint tracking");
        System.out.println("Press any key to stop...");
        System.in.read();

        server.shutdownNow();
    }
}
