package com.pki.example.repository;

import com.pki.example.model.CA;
import com.pki.example.model.CSR;
import com.pki.example.model.CSRStatus;
import com.pki.example.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CSRRepository extends JpaRepository<CSR, Long> {
    List<CSR> findByStatus(CSRStatus status);
    List<CSR> findByCaIdAndStatus(Long caId, CSRStatus status);
    List<CSR> findBySubjectContainingIgnoreCase(String subject);
    List<CSR> findBySubjectContainingIgnoreCaseAndStatus(String subject, CSRStatus status);
    List<CSR> findByUserId(Integer userId);
    List<CSR> findAllByUser(User user);
}
