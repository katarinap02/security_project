package com.pki.example.repository;

import com.pki.example.model.Certificate;
import com.pki.example.model.CertificateType;
import com.pki.example.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface CertificateRepository extends JpaRepository<Certificate, Integer> {

    Optional<Certificate> findBySerialNumber(String serialNumber);

    List<Certificate> findByIssuerAndRevokedTrue(Certificate issuer);

    List<Certificate> findByIssuerAndRevokedFalse(Certificate issuer);

    List<Certificate> findByOwner(User owner);

    List<Certificate> findByRevokedTrue();

    List<Certificate> findAllByOwnerAndType(User owner, CertificateType certificateType);

    List<Certificate> findByIssuer(Certificate issuer);
}
