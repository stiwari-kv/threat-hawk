package com.threathawk.controller;

import com.threathawk.config.AppConstants;
import com.threathawk.detection.*;
import com.threathawk.model.Alert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping(AppConstants.API_RULE_BASED)
public class RuleController {

    private static final Logger log = LoggerFactory.getLogger(RuleController.class);

    private final DetectorService detectorService;

    public RuleController(DetectorService detectorService) {
        this.detectorService = detectorService;
    }

    @GetMapping
    public ResponseEntity<List<RuleSummary>> listRules() {
        log.debug("Received request to list all rules");
        List<RuleSummary> summaries = detectorService.getRules()
                .stream()
                .map(r -> {
                    log.debug("Mapping rule -> id={}, type={}", r.getId(), r.getClass().getSimpleName());
                    return new RuleSummary(r.getId(), r.getClass().getSimpleName());
                })
                .toList();
        log.info("Returning {} rules", summaries.size());
        return ResponseEntity.ok(summaries);
    }

    @PostMapping
    public ResponseEntity<String> addRule(@RequestBody RuleConfig cfg) {
        log.debug("Received request to add rule: {}", cfg);
        try {
            Rule r = RuleFactory.create(cfg);
            log.debug("Created rule object: id={}, type={}", r.getId(), r.getClass().getSimpleName());
            detectorService.addRule(r);
            log.info("Successfully added rule: {}", cfg.id);
            return ResponseEntity.ok("Rule added: " + cfg.id);
        } catch (Exception ex) {
            log.error("Failed to add rule with id={}. Error: {}", cfg.id, ex.getMessage(), ex);
            return ResponseEntity.badRequest().body("Failed to add rule: " + ex.getMessage());
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<String> deleteRule(@PathVariable String id) {
        log.debug("Received request to delete rule: {}", id);
        boolean removed = detectorService.removeRule(id);
        if (removed) {
            log.info("Rule successfully removed: {}", id);
            return ResponseEntity.ok("Removed rule: " + id);
        } else {
            log.warn("Delete failed: Rule with id={} not found", id);
            return ResponseEntity.status(404).body("Rule not found: " + id);
        }
    }

    public record RuleSummary(String id, String type) {}
}
