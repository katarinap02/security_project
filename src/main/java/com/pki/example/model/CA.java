package com.pki.example.model;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.util.List;

@Entity
@Getter
@Setter
public class CA {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
    private int maxCertificateDuration;

    @Lob
    private byte[] certificateBytes;

    @Lob
    private byte[] privateKeyBytes;

    @OneToMany(mappedBy = "ca")
    private List<CSR> signedCSRs;

    private String keystoreFileName;

    private String keystorePassword;

    private String keyPassword;

    private boolean isRoot;

    private String serialNumber;

}
