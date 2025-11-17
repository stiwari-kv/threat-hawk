package com.threathawk.filter;

import com.threathawk.config.AppConstants;
import com.threathawk.detection.DetectorService;
import com.threathawk.model.Event;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.util.ContentCachingRequestWrapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
@Order(2)
public class RequestCaptureFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(RequestCaptureFilter.class);

    private final DetectorService detectorService;

    public RequestCaptureFilter(DetectorService detectorService) {
        this.detectorService = detectorService;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        log.debug("➡️ RequestCaptureFilter.doFilter START - method={}, URI={}, query={}, remoteAddr={}",
                httpRequest.getMethod(), httpRequest.getRequestURI(),
                httpRequest.getQueryString(), httpRequest.getRemoteAddr());

        ContentCachingRequestWrapper wrappedRequest = new ContentCachingRequestWrapper(httpRequest);
        log.debug("Wrapped HttpServletRequest into ContentCachingRequestWrapper");

        log.debug("Proceeding with wrapped request down the filter chain");
        chain.doFilter(wrappedRequest, response);

        log.debug("Building Event object from request after chain processing");
        Event event = buildEventFromRequest(wrappedRequest);

        log.debug("Passing Event to DetectorService.analyzeAndSave - path={}, method={}, ip={}", event.getPath(), event.getMethod(), event.getIp());
        detectorService.analyzeAndSave(event);

        log.info("✅ Captured Request -> method={}, URI={}, ip={}, headers={}, bodyLength={}",
                event.getMethod(),
                event.getPath(),
                event.getIp(),
                (event.getHeaders() != null ? event.getHeaders().size() : 0),
                (event.getBody() != null ? event.getBody().length() : 0));

        log.debug("➡️ RequestCaptureFilter.doFilter END - request captured and sent to detector");
    }

    private Event buildEventFromRequest(ContentCachingRequestWrapper req) {
        log.debug("🛠️ buildEventFromRequest START - URI={}, method={}, remoteAddr={}",
                req.getRequestURI(), req.getMethod(), req.getRemoteAddr());

        Event event = new Event();
        event.setTimestamp(Instant.now());
        event.setPath(req.getRequestURI());
        event.setMethod(req.getMethod());
        event.setIp(req.getRemoteAddr());

        Map<String, String> params = req.getParameterMap()
                .entrySet()
                .stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        e -> String.join(",", e.getValue())
                ));
        event.setParams(params);
        log.debug("Captured {} request parameters", params.size());

        Map<String, String> headers = Collections.list(req.getHeaderNames())
                .stream()
                .collect(Collectors.toMap(h -> h, req::getHeader));
        event.setHeaders(headers);
        log.debug("Captured {} request headers", headers.size());

        Object statusAttr = req.getAttribute(AppConstants.JAKARTA_SERVLET_ERROR_STATUS_CODE);
        if (statusAttr instanceof Integer) {
            event.setStatus((Integer) statusAttr);
            log.debug("Captured request status attribute: {}", event.getStatus());
        } else {
            log.debug("No request status attribute found, leaving null");
            event.setStatus(null);
        }

        String body = "";
        byte[] buf = req.getContentAsByteArray();
        if (buf.length > 0) {
            body = new String(buf, StandardCharsets.UTF_8);
            log.debug("Captured request body length={} chars", body.length());
        } else {
            log.debug("No body content available for request");
        }
        event.setBody(body);

        log.debug("🛠️ buildEventFromRequest END - event built successfully");
        return event;
    }
}