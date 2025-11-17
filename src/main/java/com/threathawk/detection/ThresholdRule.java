package com.threathawk.detection;

import com.threathawk.config.AppConstants;
import com.threathawk.model.Alert;
import com.threathawk.model.Event;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

public class ThresholdRule implements Rule {

    private static final Logger log = LoggerFactory.getLogger(ThresholdRule.class);

    private final String id;
    private final String path;
    private final int windowSeconds;
    private final int threshold;
    private final String severity;
    private final String description;

    private final Map<String, Deque<Instant>> counters = new ConcurrentHashMap<>();

    public ThresholdRule(RuleConfig cfg) {
        this.id = cfg.id;
        this.path = cfg.path;
        this.windowSeconds = cfg.windowSeconds;
        this.threshold = cfg.threshold;
        this.severity = cfg.severity;
        this.description = cfg.description;

        log.debug("Initialized ThresholdRule: id={}, path={}, windowSeconds={}, threshold={}, severity={}, description={}",
                id, path, windowSeconds, threshold, severity, description);
    }

    @Override
    public Optional<Alert> apply(Event event) {
        log.debug("ThresholdRule {} evaluating event: ip={}, path={}, status={}",
                id, event.getIp(), event.getPath(), event.getStatus());

        if (event.getPath() == null) {
            log.debug("Rule {} skipping event because path is null", id);
            return Optional.empty();
        }
        if (!event.getPath().startsWith(path)) {
            log.debug("Rule {} skipping event because path '{}' does not start with '{}'",
                    id, event.getPath(), path);
            return Optional.empty();
        }

        Integer status = event.getStatus();
        if (status == null || !(status == 401 || status == 403)) {
            log.debug("Rule {} skipping event because status={} is not 401/403", id, status);
            return Optional.empty();
        }

        String key = event.getIp() == null ? "unknown" : event.getIp();
        Deque<Instant> deque = counters.computeIfAbsent(key, k -> {
            log.debug("Rule {} creating new deque for ip={}", id, k);
            return new ArrayDeque<>();
        });

        Instant now = Instant.now();
        synchronized (deque) {
            deque.addLast(now);
            log.debug("Rule {} added timestamp={} for ip={}", id, now, key);

            Instant cutoff = now.minusSeconds(windowSeconds);
            while (!deque.isEmpty() && deque.peekFirst().isBefore(cutoff)) {
                Instant removed = deque.removeFirst();
                log.debug("Rule {} evicted old timestamp={} for ip={}", id, removed, key);
            }

            log.debug("Rule {} tracking ip={} -> attemptCount={} within last {}s",
                    id, key, deque.size(), windowSeconds);

            if (deque.size() >= threshold) {
                String message = AppConstants.THRESHOLD_EXCEEDED + description + AppConstants.COUNT_EQUALS + deque.size();
                String metadata = AppConstants.IP_EQUALS + key + AppConstants.PATH_EQUALS + event.getPath();
                Alert alert = new Alert(Instant.now(), id, severity, message, metadata);

                log.info("ThresholdRule {} TRIGGERED for ip={} path={} -> {}",
                        id, key, event.getPath(), message);

                deque.clear();
                log.debug("Rule {} reset counter for ip={} after triggering alert", id, key);

                return Optional.of(alert);
            }
        }

        log.debug("Rule {} did not trigger alert for ip={} (attempts={}/{})",
                id, key, counters.get(key).size(), threshold);
        return Optional.empty();
    }

    @Override
    public String getId() {
        return id;
    }
}