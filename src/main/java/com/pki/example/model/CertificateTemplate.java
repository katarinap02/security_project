package com.pki.example.model;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "certificate_templates")
@Getter
@Setter
public class CertificateTemplate {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(nullable = false, unique = true)
    private String name; // Naziv šablona

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "issuer_certificate_id", nullable = false)
    private Certificate issuerCertificate; // CA koji će izdavati po ovom šablonu

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "owner_id", nullable = false)
    private User owner;

    @Column(name = "cn_regex")
    private String commonNameRegex;

    @Column(name = "san_regex")
    private String sanRegex;

    @Column(name = "max_validity_days", nullable = false)
    private Integer maxValidityDays; // Maksimalno trajanje u danima

    @ElementCollection
    @CollectionTable(name = "template_key_usage", joinColumns = @JoinColumn(name = "template_id"))
    @Column(name = "key_usage")
    private List<String> keyUsage = new ArrayList<>();

    @ElementCollection
    @CollectionTable(name = "template_extended_key_usage", joinColumns = @JoinColumn(name = "template_id"))
    @Column(name = "extended_key_usage")
    private List<String> extendedKeyUsage = new ArrayList<>();

    @Column(name = "description")
    private String description;
}
