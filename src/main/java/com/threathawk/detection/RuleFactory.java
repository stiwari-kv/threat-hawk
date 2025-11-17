package com.threathawk.detection;

import com.threathawk.config.AppConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class RuleFactory {
    private static final Logger log = LoggerFactory.getLogger(RuleFactory.class);

    public static Rule create(RuleConfig cfg) {
        log.debug("RuleFactory.create() called. cfg == null? {}", cfg == null);

        if (cfg == null) {
            log.error("RuleFactory.create() received null RuleConfig -> throwing IllegalArgumentException");
            throw new IllegalArgumentException("RuleConfig is null");
        }

        log.debug("RuleConfig details: id='{}', type='{}', desc='{}', severity='{}', pattern='{}', field='{}', path='{}', windowSeconds='{}', threshold='{}'",
                cfg.id, cfg.type, cfg.description, cfg.severity,
                cfg.pattern, cfg.field, cfg.path,
                cfg.windowSeconds, cfg.threshold);

        try {
            if (AppConstants.REGEX.equalsIgnoreCase(cfg.type)) {
                log.debug("Detected rule type 'regex' for id='{}'. Creating RegexRule...", cfg.id);
                RegexRule r = new RegexRule(cfg);
                log.info("Created RegexRule -> id='{}', pattern='{}', field='{}'", cfg.id, cfg.pattern, r.getId());
                return r;
            } else if (AppConstants.THRESHOLD.equalsIgnoreCase(cfg.type)) {
                log.debug("Detected rule type 'threshold' for id='{}'. Creating ThresholdRule...", cfg.id);
                ThresholdRule r = new ThresholdRule(cfg);
                log.info("Created ThresholdRule -> id='{}', path='{}', windowSeconds='{}', threshold='{}'",
                        cfg.id, cfg.path, cfg.windowSeconds, cfg.threshold);
                return r;
            } else {
                log.warn("Unknown rule type '{}' for id='{}'. Supported types: regex, threshold", cfg.type, cfg.id);
                throw new IllegalArgumentException("Unknown rule type: " + cfg.type);
            }
        } catch (Exception ex) {
            log.error("Exception while creating rule id='{}' type='{}' : {}", cfg.id, cfg.type, ex.getMessage(), ex);
            throw ex;
        }
    }
}