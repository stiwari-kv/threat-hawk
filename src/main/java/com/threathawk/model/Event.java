package com.threathawk.model;

import java.time.Instant;
import java.util.Map;

public class Event {
    private Instant timestamp;
    private String method;
    private String path;
    private String ip;
    private Map<String, String> params;
    private Map<String, String> headers;
    private Integer status;
    private String body;

    public Event() { }

    public Event(Instant timestamp, String method, String path, String ip,
                 Map<String, String> params, Map<String, String> headers,
                 Integer status, String body) {
        this.timestamp = timestamp;
        this.method = method;
        this.path = path;
        this.ip = ip;
        this.params = params;
        this.headers = headers;
        this.status = status;
        this.body = body;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public Map<String, String> getParams() {
        return params;
    }

    public void setParams(Map<String, String> params) {
        this.params = params;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public void setHeaders(Map<String, String> headers) {
        this.headers = headers;
    }

    public Integer getStatus() {
        return status;
    }

    public void setStatus(Integer status) {
        this.status = status;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }
}
