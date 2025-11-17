package com.threathawk.detection;

import com.threathawk.config.AppConstants;
import com.threathawk.model.Alert;
import com.threathawk.model.Event;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class RegexRule implements Rule {

    private static final Logger log = LoggerFactory.getLogger(RegexRule.class);
    private final String id;
    private final Pattern pattern;
    private final List<String> fields;
    private final String severity;
    private final String description;

    private static final String[] ALLOWED_USER_AGENTS = {
            "Mozilla", "Chrome", "PostmanRuntime", "curl/7", "Wget"
    };

    private static final Set<String> SENSITIVE_HEADERS =
            Set.of("authorization", "cookie", "set-cookie");

    private static final int MIN_MATCH_LENGTH = 3;

    public RegexRule(RuleConfig cfg) {
        this.id = cfg.id;
        this.pattern = Pattern.compile(cfg.pattern);
        this.severity = cfg.severity;
        this.description = cfg.description;
        List<String> tmp = new ArrayList<>();
        if (cfg.fields != null && !cfg.fields.isEmpty()) {
            cfg.fields.stream()
                    .filter(f -> f != null && !f.isBlank())
                    .map(String::toLowerCase)
                    .forEach(tmp::add);
        } else if (cfg.field != null && !cfg.field.isBlank()) {
            String[] split = cfg.field.split(",");
            for (String f : split) {
                tmp.add(f.trim().toLowerCase());
            }
        } else {
            tmp.add("body");
        }
        this.fields = List.copyOf(tmp);
        log.debug("Initialized RegexRule: id={}, pattern={}, fields={}, severity={}, description={}",
                id, cfg.pattern, fields, severity, description);
    }

    @Override
    public Optional<Alert> apply(Event event) {
        log.debug("RegexRule {} applying on event: ip={}, path={}, params={}", id, event.getIp(), event.getPath(), event.getParams());
        String combinedValue = buildCombinedValue(event);
        if ((fields.contains("headers") || fields.contains("any")) && isUserAgentAllowlisted(event)) {
            log.debug("Rule {} skipped due to allowlisted User-Agent", id);
            return Optional.empty();
        }
        Matcher matcher = pattern.matcher(combinedValue);
        if (!matcher.find()) {
            log.debug("RegexRule {} did NOT match. ip={}, path={}, fields={}, valueLength={}",
                    id, event.getIp(), event.getPath(), fields, combinedValue.length());
            return Optional.empty();
        }
        String matchedText = matcher.group();
        if (matchedText == null || matchedText.length() < MIN_MATCH_LENGTH) {
            log.debug("RegexRule {} matched too-short token '{}' - likely FP, skipping.", id, matchedText);
            return Optional.empty();
        }
        String matchedField = detectMatchedField(event);
        String message = AppConstants.REGEX_MATCH + description + AppConstants.FIELD_EQUALS + matchedField + AppConstants.CLOSING_BRACKET;
        String metadata = AppConstants.IP_EQUALS + event.getIp() + AppConstants.PATH_EQUALS + event.getPath()
                + ", matchedSnippet=" + truncate(matchedText, 200);
        Alert alert = new Alert(Instant.now(), id, severity, message, metadata);
        log.info("🚨 RegexRule {} TRIGGERED! ip={}, path={}, matchedField={}, snippet='{}'",
                id, event.getIp(), event.getPath(), matchedField, truncate(matchedText, 80));
        return Optional.of(alert);
    }

    /**Combine values from the requested fields **/
    private String buildCombinedValue(Event event) {
        StringBuilder sb = new StringBuilder();
        for (String field : fields) {
            switch (field) {
                case "any":
                    appendPath(sb, event);
                    appendBody(sb, event);
                    appendParams(sb, event);
                    appendHeaders(sb, event);
                    break;
                case "path":
                    appendPath(sb, event);
                    break;
                case "body":
                    appendBody(sb, event);
                    break;
                case "params":
                    appendParams(sb, event);
                    break;
                case "headers":
                    appendHeaders(sb, event);
                    break;
                default:
                    log.debug("RegexRule {}: Unknown field '{}'", id, field);
            }
            sb.append(" ");
        }
        return sb.toString().trim();
    }

    private void appendPath(StringBuilder sb, Event event) {
        if (event.getPath() != null) sb.append(event.getPath());
    }

    private void appendBody(StringBuilder sb, Event event) {
        if (event.getBody() != null && !event.getBody().isEmpty()) sb.append(event.getBody());
    }

    private void appendParams(StringBuilder sb, Event event) {
        if (event.getParams() != null && !event.getParams().isEmpty()) {
            String combined = event.getParams().entrySet().stream()
                    .map(e -> e.getKey() + "=" + e.getValue())
                    .collect(Collectors.joining(" "));
            sb.append(combined);
        }
    }

    private void appendHeaders(StringBuilder sb, Event event) {
        if (event.getHeaders() != null) {
            event.getHeaders().forEach((k,v) -> {
                String key = k.toLowerCase();
                if (SENSITIVE_HEADERS.contains(key)) {
                    sb.append(key).append(": [REDACTED] ");
                } else {
                    sb.append(k).append(": ").append(v).append(" ");
                }
            });
        }
    }

    private boolean isUserAgentAllowlisted(Event event) {
        if (event.getHeaders() == null) return false;
        String ua = Optional.ofNullable(event.getHeaders().get("User-Agent"))
                .orElse(event.getHeaders().get("user-agent"));
        if (ua == null) return false;
        for (String prefix : ALLOWED_USER_AGENTS) {
            if (ua.startsWith(prefix)) return true;
        }
        return false;
    }

    private String detectMatchedField(Event event) {
        for (String f : fields) {
            switch (f) {
                case "any":
                    String pathVal = Optional.ofNullable(event.getPath()).orElse("");
                    if (!pathVal.isEmpty() && pattern.matcher(pathVal).find()) return "path";
                    String params = event.getParams() != null
                            ? event.getParams().entrySet().stream()
                            .map(e -> e.getKey() + "=" + e.getValue())
                            .collect(Collectors.joining(" "))
                            : "";
                    if (!params.isEmpty() && pattern.matcher(params).find()) return "params";
                    String headers = event.getHeaders() != null
                            ? event.getHeaders().entrySet().stream()
                            .map(e -> e.getKey() + ": " + e.getValue())
                            .collect(Collectors.joining(" "))
                            : "";
                    if (!headers.isEmpty() && pattern.matcher(headers).find()) return "headers";
                    String bodyVal = Optional.ofNullable(event.getBody()).orElse("");
                    if (!bodyVal.isEmpty() && pattern.matcher(bodyVal).find()) return "body";
                    return "unknown";
                case "path":
                    if (pattern.matcher(Optional.ofNullable(event.getPath()).orElse("")).find()) return "path";
                    break;
                case "params":
                    String paramsStr = event.getParams() != null
                            ? event.getParams().entrySet().stream()
                            .map(e -> e.getKey() + "=" + e.getValue())
                            .collect(Collectors.joining(" "))
                            : "";
                    if (pattern.matcher(paramsStr).find()) return "params";
                    break;
                case "headers":
                    String headersStr = event.getHeaders() != null
                            ? event.getHeaders().entrySet().stream()
                            .map(e -> e.getKey() + ": " + e.getValue())
                            .collect(Collectors.joining(" "))
                            : "";
                    if (pattern.matcher(headersStr).find()) return "headers";
                    break;
                case "body":
                    if (pattern.matcher(Optional.ofNullable(event.getBody()).orElse("")).find()) return "body";
                    break;
            }
        }
        return "unknown";
    }

    private String truncate(String text, int limit) {
        if (text == null) return "";
        return text.length() > limit ? text.substring(0, limit) + "..." : text;
    }

    @Override
    public String getId() {
        return id;
    }
}
