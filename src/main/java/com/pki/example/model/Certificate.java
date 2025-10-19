package com.pki.example.model;

import com.fasterxml.jackson.annotation.*;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.util.Date;

@Entity
@Table(name = "certificates")
@JsonIdentityInfo(
        generator = ObjectIdGenerators.PropertyGenerator.class,
        property = "id"
)
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
@Getter
@Setter
public class Certificate {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(unique = true, nullable = false)
    private String serialNumber;

    @Column(nullable = false)
    @Temporal(TemporalType.TIMESTAMP)
    private Date validFrom;

    @Column(nullable = false)
    @Temporal(TemporalType.TIMESTAMP)
    private Date validTo;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CertificateType type;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "issuer_id")
    @JsonIgnore
    private Certificate issuer;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "owner_id")
    @JsonBackReference
    private User owner;

    // ✅ Revocation polja
    @Column(name = "is_revoked")
    private boolean revoked = false;  // ✅ Jednostavnije

    @Enumerated(EnumType.STRING)
    @Column(name = "revocation_reason")
    private RevocationReason revocationReason;

    @Column(name = "revocation_date")
    @Temporal(TemporalType.TIMESTAMP)
    private Date revocationDate;

    // Keystore polja
    @Column(nullable = false)
    private String keystoreFileName;

    @Column(nullable = false)
    private String encryptedKeystorePassword;

    @Column(name = "allowed_key_usages", length = 500)
    private String allowedKeyUsages;

    @Column(name = "allowed_extended_key_usages", length = 500)
    private String allowedExtendedKeyUsages;

    // Konstruktori
    public Certificate() {}

    public Certificate(String serialNumber, Date validFrom, Date validTo,
                       CertificateType type, String keystoreFileName,
                       String encryptedKeystorePassword) {
        this.serialNumber = serialNumber;
        this.validFrom = validFrom;
        this.validTo = validTo;
        this.type = type;
        this.keystoreFileName = keystoreFileName;
        this.encryptedKeystorePassword = encryptedKeystorePassword;
    }

}