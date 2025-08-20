package com.pki.example.repository;

import com.pki.example.model.Certificate;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CertificateRepository extends JpaRepository<Certificate, Integer> {

    Optional<Certificate> findBySerialNumber(String serialNumber);
}
