package com.threathawk.controller;

import com.threathawk.config.AppConstants;
import com.threathawk.detection.DetectorService;
import com.threathawk.model.Alert;
import com.threathawk.model.Event;
import com.threathawk.repository.AlertRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping(AppConstants.PATH_API)
public class AlertController {

    private static final Logger log = LoggerFactory.getLogger(AlertController.class);

    private final DetectorService detectorService;
    private final AlertRepository alertRepository;

    public AlertController(DetectorService detectorService, AlertRepository alertRepository) {
        this.detectorService = detectorService;
        this.alertRepository = alertRepository;
    }

    @PostMapping(AppConstants.PATH_EVENTS)
    public void postEvent(@RequestBody Event event) {
        log.info("Received new event for analysis: method={}, path={}, ip={}, body={}",
                event.getMethod(), event.getPath(), event.getIp(), event.getBody());
    }

    @GetMapping(AppConstants.PATH_ALERTS)
    public Page<Alert> getAlerts(@RequestParam(defaultValue = "0") int page,
                                 @RequestParam(defaultValue = "20") int size) {
        log.debug("Fetching paginated alerts: page={}, size={}", page, size);
        return alertRepository.findAll(PageRequest.of(page, size));
    }

    @GetMapping(AppConstants.PATH_ALERTS_ALL)
    public List<Alert> getAllAlerts() {
        log.warn("Fetching ALL alerts (not recommended for production).");
        return alertRepository.findAll();
    }
}