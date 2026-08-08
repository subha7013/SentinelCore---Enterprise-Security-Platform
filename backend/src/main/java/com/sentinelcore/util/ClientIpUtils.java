package com.sentinelcore.util;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

public class ClientIpUtils {

    private static final String[] IP_HEADER_CANDIDATES = {
        "X-Forwarded-For",
        "X-Real-IP",
        "CF-Connecting-IP",
        "True-Client-IP",
        "Proxy-Client-IP",
        "WL-Proxy-Client-IP",
        "HTTP_X_FORWARDED_FOR",
        "HTTP_X_FORWARDED",
        "HTTP_X_CLUSTER_CLIENT_IP",
        "HTTP_CLIENT_IP",
        "HTTP_FORWARDED_FOR",
        "HTTP_FORWARDED",
        "HTTP_VIA",
        "REMOTE_ADDR"
    };

    /**
     * Extracts the true client IP address from request headers when behind reverse proxies,
     * load balancers, or Cloudflare, falling back to request.getRemoteAddr().
     */
    public static String getClientIpAddress(HttpServletRequest request) {
        if (request == null) {
            return "0.0.0.0";
        }

        for (String header : IP_HEADER_CANDIDATES) {
            String ipList = request.getHeader(header);
            if (StringUtils.hasText(ipList) && !"unknown".equalsIgnoreCase(ipList)) {
                // X-Forwarded-For can contain multiple IPs separated by comma (client, proxy1, proxy2)
                String[] ips = ipList.split(",");
                for (String ip : ips) {
                    String trimmedIp = ip.trim();
                    if (isValidIp(trimmedIp)) {
                        return trimmedIp;
                    }
                }
            }
        }

        String remoteAddr = request.getRemoteAddr();
        if ("0:0:0:0:0:0:0:1".equals(remoteAddr)) {
            return "127.0.0.1";
        }
        return StringUtils.hasText(remoteAddr) ? remoteAddr : "0.0.0.0";
    }

    private static boolean isValidIp(String ip) {
        if (!StringUtils.hasText(ip) || "unknown".equalsIgnoreCase(ip)) {
            return false;
        }
        // Basic filter for invalid/empty IP strings
        return true;
    }
}
