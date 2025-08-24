package com.pki.example.service;

import com.pki.example.model.AuditLog;
import com.pki.example.repository.AuditLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
public class AuditLogService {

    @Autowired
    private AuditLogRepository auditLogRepository;

    public void logEvent(String email, String action, String ip, String userAgent, String status, String details) {
        AuditLog log = new AuditLog();
        log.setEmail(email);
        log.setAction(action);
        log.setIpAddress(ip);
        log.setUserAgent(userAgent);
        log.setTimestamp(LocalDateTime.now());
        log.setStatus(status);
        log.setDetails(details);
        auditLogRepository.save(log);
    }
}
