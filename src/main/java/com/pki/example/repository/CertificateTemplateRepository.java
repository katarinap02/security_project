package com.pki.example.repository;

import com.pki.example.data.Issuer;
import com.pki.example.model.Certificate;
import com.pki.example.model.CertificateTemplate;
import com.pki.example.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CertificateTemplateRepository extends JpaRepository<CertificateTemplate, Integer> {

    List<CertificateTemplate> findByOwner(User user);

    List<CertificateTemplate> findByIssuerCertificate(Certificate certificate);
}
