package com.pki.example.dto;

import com.pki.example.model.CertificateType;
import lombok.Data;
import org.bouncycastle.asn1.x500.X500Name;

import java.util.Date;
@Data
public class IssuerCertificateDTO {

    // Podaci potrebni za X500Name
    private String commonName;
    private String surname;
    private String givenName;
    private String organization;
    private String organizationalUnit;
    private String country;
    private String email;
    private String ownerEmail;

    private String type;

    private Date validFrom;
    private Date validTo;

    //serijski broj izdavaoca, ako je root onda je prazan string
    private String issuerSerialNumber;
}
