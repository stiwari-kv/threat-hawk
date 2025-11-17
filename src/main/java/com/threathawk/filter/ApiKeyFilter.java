package com.threathawk.filter;

import com.threathawk.config.AppConstants;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
@Order(1)
public class ApiKeyFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(ApiKeyFilter.class);
    private final Environment env;
    private final String headerName = "X-API-KEY";

    public ApiKeyFilter(Environment env) {
        this.env = env;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest r = (HttpServletRequest) request;
        String path = r.getRequestURI();

        log.debug("ApiKeyFilter.doFilter START - method={}, path={}, query={}, remoteAddr={}",
                r.getMethod(), path, r.getQueryString(), r.getRemoteAddr());

        if (path.startsWith(AppConstants.PATH_API_ALERTS) || path.startsWith(AppConstants.PATH_API_EVENTS) || path.startsWith(AppConstants.API_RULE_BASED)) {
            log.debug("Path requires API key protection: {}", path);

            String requiredKey = resolveKeyForPath(path);
            String providedKey = r.getHeader(headerName);

            log.debug("Resolved requiredKey (masked)={} ; providedKey header present={}",
                    maskKey(requiredKey), (providedKey != null));

            if (requiredKey.isBlank()) {
                log.info("No API key configured for path='{}'. Allowing request (dev mode).", path);
                try {
                    chain.doFilter(request, response);
                } catch (Exception ex) {
                    log.error("Exception while processing request for path='{}': {}", path, ex.getMessage(), ex);
                    throw ex;
                }
                log.debug("ApiKeyFilter.doFilter END after allowing (no key configured) - path={}", path);
                return;
            }

            if (!requiredKey.equals(providedKey)) {
                log.warn("Unauthorized access attempt. path={}, method={}, remoteAddr={}, providedKeyMasked={}, requiredKeyMasked={}",
                        path, r.getMethod(), r.getRemoteAddr(), maskKey(providedKey), maskKey(requiredKey));

                HttpServletResponse resp = (HttpServletResponse) response;
                resp.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                resp.getWriter().write(AppConstants.ANAUTHORIZED);
                log.debug("ApiKeyFilter.doFilter END - returned 401 for path={}", path);
                return;
            }

            log.debug("API key validated for path={} ; proceeding to next filter/servlet", path);
            try {
                chain.doFilter(request, response);
            } catch (Exception ex) {
                log.error("Exception while processing request for path='{}': {}", path, ex.getMessage(), ex);
                throw ex;
            }

            if (response instanceof HttpServletResponse) {
                int status = ((HttpServletResponse) response).getStatus();
                log.debug("Completed request for path={} ; responseStatus={}", path, status);
            } else {
                log.debug("Completed request for path={} ; response object not an HttpServletResponse", path);
            }

            log.debug("ApiKeyFilter.doFilter END - path={}", path);
            return;
        }

        log.debug("Path does not require API key protection. Passing through: {}", path);
        chain.doFilter(request, response);
        log.debug("ApiKeyFilter.doFilter END (non-protected path) - path={}", path);
    }

    /**
     * Decide which property should be used for the given path and log which property we used.
     */
    private String resolveKeyForPath(String path) {
        String prop;
        if (path.startsWith(AppConstants.PATH_API_ALERTS)) {
            prop = AppConstants.PROP_API_KEY_ALERTS;
        } else if (path.startsWith(AppConstants.PATH_API_EVENTS)) {
            prop = AppConstants.PROP_API_KEY_EVENTS;
        } else if (path.startsWith(AppConstants.API_RULE_BASED)) {
            prop = AppConstants.PROP_API_KEY_RULES;
        } else {
            prop = AppConstants.PROP_API_KEY_GLOBAL;
        }

        String value = env.getProperty(prop, "");
        log.debug("resolveKeyForPath -> selectedProperty='{}' maskedValue='{}' for path='{}'", prop, maskKey(value), path);
        return value;
    }

    /**
     * Mask keys for safe logging. Returns a human-readable masked string.
     */
    private String maskKey(String key) {
        if (key == null || key.isBlank()) return AppConstants.NOT_CONFIGURED;
        int len = key.length();
        if (len <= 4) return AppConstants.MASKED;

        return AppConstants.MASKED + key.substring(len - 4);
    }
}