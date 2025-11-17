package com.threathawk.detection;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class RuleConfig {
    public String id;
    public String type;
    public String description;
    public String severity;
    // for regex
    public String pattern;
    public String field;
    public List<String> fields;
    // for threshold
    public String path;
    public int windowSeconds;
    public int threshold;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    public String getPattern() { return pattern; }
    public void setPattern(String pattern) { this.pattern = pattern; }
    public String getField() { return field; }
    public void setField(String field) { this.field = field; }
    public List<String> getFields() { return fields; }
    public void setFields(List<String> fields) { this.fields = fields; }
    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }
    public int getWindowSeconds() { return windowSeconds; }
    public void setWindowSeconds(int windowSeconds) { this.windowSeconds = windowSeconds; }
    public int getThreshold() { return threshold; }
    public void setThreshold(int threshold) { this.threshold = threshold; }
}
