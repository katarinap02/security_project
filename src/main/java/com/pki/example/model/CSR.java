package com.pki.example.model;

import com.pki.example.data.Subject;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import javax.persistence.*;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.Base64;

@Entity
@Table(name="csr")
@Getter
@Setter
public class CSR {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ca_id", nullable = true)
    private CA ca;

    @Lob
    @Column(nullable = false, columnDefinition = "TEXT")
    private String subject;

    @Lob
    @Column(nullable = false)
    private String csrPem;

    @Lob
    @Column(nullable = false)
    private byte[] publicKey;

    @Enumerated(EnumType.STRING)
    private CSRType type;

    private Integer requestedValidityDays;

    @Enumerated(EnumType.STRING)
    private CSRStatus status = CSRStatus.PENDING;

    private LocalDateTime createdAt = LocalDateTime.now();


    public Subject toSubject(String cn, String surname, String givenName,
                             String organization, String organizationalUnit,
                             String country, String email) {
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(
                new ByteArrayInputStream(this.csrPem.getBytes(StandardCharsets.UTF_8))))) {

            PKCS10CertificationRequest csrRequest = (PKCS10CertificationRequest) pemParser.readObject();

            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            PublicKey publicKey = converter.getPublicKey(csrRequest.getSubjectPublicKeyInfo());

            // Kreiranje X500Name sa podacima iz forme
            X500Name x500Name = new X500NameBuilder(BCStyle.INSTANCE)
                    .addRDN(BCStyle.CN, cn)
                    .addRDN(BCStyle.SURNAME, surname)
                    .addRDN(BCStyle.GIVENNAME, givenName)
                    .addRDN(BCStyle.O, organization)
                    .addRDN(BCStyle.OU, organizationalUnit)
                    .addRDN(BCStyle.C, country)
                    .addRDN(BCStyle.EmailAddress, email)
                    .build();

            return new Subject(publicKey, x500Name);

        } catch (Exception e) {
            throw new RuntimeException("Ne mogu da konvertujem CSR u Subject: " + e.getMessage(), e);
        }
    }

}
