package com.threathawk.repository;

import com.threathawk.model.Alert;
import org.springframework.stereotype.Repository;
import org.springframework.data.mongodb.repository.MongoRepository;
@Repository

public interface AlertRepository extends MongoRepository<Alert, String> {
}
