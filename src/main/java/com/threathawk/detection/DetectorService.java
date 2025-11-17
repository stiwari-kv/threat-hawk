package com.threathawk.detection;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.threathawk.model.Alert;
import com.threathawk.model.Event;
import com.threathawk.repository.AlertRepository;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class DetectorService {

    private static final Logger log = LoggerFactory.getLogger(DetectorService.class);

    private final AlertRepository alertRepository;
    // thread-safe list so rules can be added/removed at runtime
    private final List<Rule> rules = new CopyOnWriteArrayList<>();

    public DetectorService(AlertRepository alertRepository) {
        this.alertRepository = alertRepository;
    }

    @PostConstruct
    public void loadRules() {
        log.debug("Entering loadRules() - starting to load detection rules from rules.json");
        try {
            ObjectMapper mapper = new ObjectMapper();
            InputStream is = new ClassPathResource("rules.json").getInputStream();
            List<RuleConfig> configs = mapper.readValue(is, new TypeReference<List<RuleConfig>>() {});
            log.debug("Parsed {} rule configs from rules.json", configs.size());
            for (RuleConfig cfg : configs) {
                Rule r = RuleFactory.create(cfg);
                rules.add(r);
                log.info("Loaded rule: id={}, type={}, field={}, severity={}",
                        cfg.id, cfg.type, cfg.field, cfg.severity);
            }
            log.info("Successfully loaded {} detection rules", rules.size());
        } catch (Exception e) {
            log.error("Failed to load rules.json: {}", e.getMessage(), e);
        }
    }

    public List<Rule> getRules() {
        log.debug("Returning {} rules via getRules()", rules.size());
        return Collections.unmodifiableList(rules);
    }

    public void addRule(Rule rule) {
        log.debug("Entering addRule() with rule={}", rule != null ? rule.getId() : "null");
        if (rule == null) {
            log.warn("addRule() was called with a null rule, skipping");
            return;
        }
        rules.add(rule);
        log.info("Added rule dynamically: {}", rule.getId());
        log.debug("Current total rules after add: {}", rules.size());
    }

    public boolean removeRule(String ruleId) {
        log.debug("Entering removeRule() with ruleId={}", ruleId);
        boolean removed = rules.removeIf(r -> r.getId().equals(ruleId));
        if (removed) {
            log.info("Removed rule: {}", ruleId);
        } else {
            log.warn("Tried to remove non-existent rule: {}", ruleId);
        }
        log.debug("Current total rules after remove: {}", rules.size());
        return removed;
    }

    public List<Alert> analyze(Event event) {
        log.debug("Entering analyze() with event: {}", event);
        List<Alert> alerts = new ArrayList<>();
        for (Rule rule : rules) {
            log.debug("Applying rule={}", rule.getId());
            try {
                Optional<Alert> maybe = rule.apply(event);
                maybe.ifPresent(alert -> {
                    alerts.add(alert);
                    log.info("Rule {} triggered alert: {}", rule.getId(), alert.getMessage());
                });
            } catch (Exception ex) {
                log.error("Rule {} failed: {}", rule.getId(), ex.getMessage(), ex);
            }
        }
        log.debug("Exiting analyze() with total alerts={}", alerts.size());
        return alerts;
    }

    public void analyzeAndSave(Event event) {
        log.debug("Entering analyzeAndSave() with event={}", event);
        List<Alert> alerts = analyze(event);
        log.info("Generated {} alerts for event={}", alerts.size());
        for (Alert a : alerts) {
            log.debug("Persisting alert: {}", a);
            try {
                alertRepository.save(a);
                log.info("Persisted alert successfully: ruleId={}, message={}", a.getRuleId(), a.getMessage());
            } catch (Exception ex) {
                log.error("Failed to persist alert for event: {}",ex.getMessage(), ex);
            }
        }
        log.debug("Exiting analyzeAndSave()");
    }
}
