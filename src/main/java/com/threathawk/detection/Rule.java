package com.threathawk.detection;

import com.threathawk.model.Alert;
import com.threathawk.model.Event;

import java.util.Optional;

public interface Rule {
    Optional<Alert> apply(Event event);
    String getId();
}
