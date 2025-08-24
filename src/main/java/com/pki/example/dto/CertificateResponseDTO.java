package com.pki.example.dto;

import com.pki.example.model.Certificate;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@NoArgsConstructor
public class CertificateResponseDTO {

    private Integer id;
    private String serialNumber;
    private String type;
    private Date validFrom;
    private Date validTo;
    private boolean isRevoked;
    private String ownerEmail;
    private String issuerSerialNumber;

    public CertificateResponseDTO(Certificate certificate) {
        this.id = certificate.getId();
        this.serialNumber = certificate.getSerialNumber();
        this.type = certificate.getType().name(); // Pretvaramo Enum u String
        this.validFrom = certificate.getValidFrom();
        this.validTo = certificate.getValidTo();
        this.isRevoked = certificate.isRevoked();

        // Bezbedna provera pre pristupanja ugnježdenim objektima
        if (certificate.getOwner() != null) {
            this.ownerEmail = certificate.getOwner().getEmail();
        }

        if (certificate.getIssuer() != null) {
            this.issuerSerialNumber = certificate.getIssuer().getSerialNumber();
        }
    }
}
