package com.threathawk.model;

import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.annotation.Id;
import java.time.Instant;

@Document(collection = "alerts")
public class Alert {
    @Id
    private String id;
    private Instant timestamp;
    private String ruleId;
    private String severity;
    private String message;
    private String metadata;

    public Alert() { }

    public Alert(Instant timestamp, String ruleId, String severity, String message, String metadata) {
        this.timestamp = timestamp;
        this.ruleId = ruleId;
        this.severity = severity;
        this.message = message;
        this.metadata = metadata;
    }
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }

    public String getRuleId() {
        return ruleId;
    }

    public void setRuleId(String ruleId) {
        this.ruleId = ruleId;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getMetadata() {
        return metadata;
    }

    public void setMetadata(String metadata) {
        this.metadata = metadata;
    }
}
