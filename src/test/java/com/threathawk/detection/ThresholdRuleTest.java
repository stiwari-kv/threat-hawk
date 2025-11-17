package com.threathawk.detection;

import com.threathawk.model.Event;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Collections;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class ThresholdRuleTest {

    @Test
    void thresholdRuleShouldTriggerAfterNFailures() {
        RuleConfig cfg = new RuleConfig();
        cfg.id = "failed_logins"; cfg.type = "threshold"; cfg.path = "/login"; cfg.windowSeconds = 60; cfg.threshold = 3; cfg.severity = "HIGH"; cfg.description = "failed logins";
        ThresholdRule r = new ThresholdRule(cfg);

        Event e1 = new Event(Instant.now(), "POST", "/login", "10.0.0.1", Collections.emptyMap(), Collections.emptyMap(), 401, null);
        Event e2 = new Event(Instant.now(), "POST", "/login", "10.0.0.1", Collections.emptyMap(), Collections.emptyMap(), 401, null);
        Event e3 = new Event(Instant.now(), "POST", "/login", "10.0.0.1", Collections.emptyMap(), Collections.emptyMap(), 401, null);

        assertTrue(r.apply(e1).isEmpty());
        assertTrue(r.apply(e2).isEmpty());
        Optional<com.threathawk.model.Alert> maybe = r.apply(e3);
        assertTrue(maybe.isPresent());
    }

}