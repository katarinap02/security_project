package com.pki.example.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class CertificateTemplateDTO {
    private Integer id;
    private String name;
    private String issuerSerialNumber; // Serijski broj CA issuer-a
    private String description;

    // Validacioni regex
    private String commonNameRegex;
    private String sanRegex;

    // TTL
    private Integer maxValidityDays;

    // Key Usage
    private List<String> keyUsage;
    private List<String> extendedKeyUsage;

    public CertificateTemplateDTO() {}
}
