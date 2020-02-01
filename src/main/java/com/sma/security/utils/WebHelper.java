package com.sma.security.utils;

import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Collection;
import java.util.Collections;
import java.util.Locale;
import java.util.Optional;

@Slf4j
public final class WebHelper {

    private WebHelper() {
        // nothing to do
    }

    public static String getClientIpAddress(HttpServletRequest request) {
        String remoteAddr = "";
        if (request != null) {
            remoteAddr = request.getHeader("X-FORWARDED-FOR");
            if (StringUtils.isEmpty(remoteAddr)) {
                remoteAddr = request.getRemoteAddr();
            }
        }
        return remoteAddr;
    }

    public static String getUserAgent(HttpServletRequest request) {
        String ua = "";
        if (request != null) {
            ua = request.getHeader("User-Agent");
        }
        return ua;
    }

    public static HttpServletRequest getCurrentRequest() {
        final RequestAttributes requestObj = RequestContextHolder.getRequestAttributes();
        return requestObj == null ? null : ((ServletRequestAttributes) requestObj).getRequest();
    }

    public static String getOS(String userAgent) {

        if (StringUtils.isEmpty(userAgent)) {
            return null;
        }
        String os = null;
        final String ua = userAgent.toLowerCase(Locale.ENGLISH);
        log.info("User Agent for the request is {} ", userAgent);
        // =================OS=======================
        if (ua.indexOf("windows") >= 0) {
            os = "Windows";
        } else if (ua.indexOf("mac") >= 0) {
            os = "Mac";
        } else if (ua.indexOf("x11") >= 0) {
            os = "Unix";
        } else if (ua.indexOf("android") >= 0) {
            os = "Android";
        } else if (ua.indexOf("iphone") >= 0) {
            os = "IPhone";
        } else {
            os = "UnKnown";
        }
        return os;
    }


    public static <T> Collection<T> getSafeList(Collection<T> collection) {
        return Optional.ofNullable(collection).orElse(Collections.emptySet());
    }

    public static Double convert(Double value, int precision) {
        try {
            return BigDecimal.valueOf(value).setScale(precision, RoundingMode.HALF_UP).doubleValue();
        } catch (NumberFormatException e) {
            log.warn(" value {} - error", value, e.getMessage(), e);
        }
        return 0.0d;
    }

}
