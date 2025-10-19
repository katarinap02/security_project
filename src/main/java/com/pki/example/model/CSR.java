package com.pki.example.model;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.time.LocalDateTime;

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

}
