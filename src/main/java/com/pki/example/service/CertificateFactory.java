package com.pki.example.service;

import com.pki.example.dto.IssuerCertificateDTO;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.springframework.stereotype.Component;

import java.security.*;
import com.pki.example.data.Issuer;
import com.pki.example.data.Subject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;

@Component
public class CertificateFactory {

    //vraca javni i privatni kljuc
    public KeyPair generateKeyPair() {
        try {
            //biblioteke za generisanje kljuceva
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
            keyGen.initialize(2048, random);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            // U pravoj aplikaciji, ovde bi bio bolji logging
            throw new RuntimeException("Failed to generate key pair.", e);
        }
    }
    public Subject createSubject(IssuerCertificateDTO dto, PublicKey publicKey) {
        X500Name x500Name = createX500NameFromDTO(dto);
        return new Subject(publicKey, x500Name);
    }

    public Issuer createIssuer(PrivateKey privateKey, PublicKey publicKey, X500Name x500Name) {
        return new Issuer(privateKey, publicKey, x500Name);
    }
    private X500Name createX500NameFromDTO(IssuerCertificateDTO dto) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, dto.getCommonName());
        builder.addRDN(BCStyle.SURNAME, dto.getSurname());
        builder.addRDN(BCStyle.GIVENNAME, dto.getGivenName());
        builder.addRDN(BCStyle.O, dto.getOrganization());
        builder.addRDN(BCStyle.OU, dto.getOrganizationalUnit());
        builder.addRDN(BCStyle.C, dto.getCountry());
        builder.addRDN(BCStyle.E, dto.getEmail());
        builder.addRDN(BCStyle.UID, dto.getEmail());
        return builder.build();
    }
}
