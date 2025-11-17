package com.threathawk.detection;

import com.threathawk.model.Event;
import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.Collections;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class RegexRuleTest {

    @Test
    void regexRuleShouldTriggerOnBodySqli() {
        RuleConfig cfg = new RuleConfig();
        cfg.id = "t1"; cfg.type = "regex"; cfg.pattern = "(?i)union\\s+select"; cfg.field = "body"; cfg.severity = "MEDIUM"; cfg.description = "sqli";
        RegexRule r = new RegexRule(cfg);

        Event e = new Event(Instant.now(), "POST", "/search", "1.2.3.4", Collections.emptyMap(), Collections.emptyMap(), 200, "something UNION SELECT password from users");
        Optional<com.threathawk.model.Alert> a = r.apply(e);
        assertTrue(a.isPresent());
    }
}