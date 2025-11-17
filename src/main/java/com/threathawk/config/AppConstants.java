package com.threathawk.config;

public final class AppConstants {

    private AppConstants() {} // prevent instantiation

    // === API Keys & Header Names ===
    public static final String HEADER_API_KEY = "X-API-KEY";

    // === Path Prefixes ===
    public static final String PATH_API = "/api";
    public static final String PATH_ALERTS = "/alerts";
    public static final String PATH_ALERTS_ALL = "/alerts/all";
    public static final String PATH_EVENTS = "/events";
    public static final String API_RULE_BASED  = "/api/rules";
    public static final String PATH_API_ALERTS = "/api/alerts";
    public static final String PATH_API_EVENTS = "/api/events";
    // === Property Keys ===
    public static final String PROP_API_KEY_GLOBAL = "threathawk.api.key";
    public static final String PROP_API_KEY_ALERTS = "threathawk.api.key.alerts";
    public static final String PROP_API_KEY_EVENTS = "threathawk.api.key.events";
    public static final String PROP_API_KEY_RULES  = "threathawk.api.key.rules";

    // === Conditional Keys ===
    public static final String REGEX = "regex";
    public static final String THRESHOLD = "threshold";
    public static final String REGEX_MATCH = "Regex match: ";
    public static final String FIELD_EQUALS = " (field=";
    public static final String CLOSING_BRACKET = ")";
    public static final String IP_EQUALS = "ip=";
    public static final String PATH_EQUALS = ", path=";
    public static final String THRESHOLD_EXCEEDED = "Threshold exceeded: ";
    public static final String COUNT_EQUALS = "count=";
    public static final String ANAUTHORIZED = "Unauthorized";
    public static final String NOT_CONFIGURED = "<not-configured>";
    public static final String MASKED = "****";
    public static final String JAKARTA_SERVLET_ERROR_STATUS_CODE = "jakarta.servlet.error.status_code";

}
