package com.pki.example.keystores;

import com.pki.example.data.Issuer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;


@Component
public class KeyStoreReader {
    //KeyStore je Java klasa za citanje specijalizovanih datoteka koje se koriste za cuvanje kljuceva
    //Tri tipa entiteta koji se obicno nalaze u ovakvim datotekama su:
    // - Sertifikati koji ukljucuju javni kljuc
    // - Privatni kljucevi
    // - Tajni kljucevi, koji se koriste u simetricnima siframa
    private KeyStore keyStore;

    private static final Logger logger = LoggerFactory.getLogger(KeyStoreReader.class);

    public KeyStoreReader() {
        try {
            keyStore = KeyStore.getInstance("JKS", "SUN");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
    }

    /**
     * Zadatak ove funkcije jeste da ucita podatke o izdavaocu i odgovarajuci privatni kljuc.
     * Ovi podaci se mogu iskoristiti da se novi sertifikati izdaju.
     *
     * @param keyStoreFile - datoteka odakle se citaju podaci
     * @param alias - alias putem kog se identifikuje sertifikat izdavaoca
     * @param password - lozinka koja je neophodna da se otvori key store
     * @param keyPass - lozinka koja je neophodna da se izvuce privatni kljuc
     * @return - podatke o izdavaocu i odgovarajuci privatni kljuc
     */
    public Issuer readIssuerFromStore(String keyStoreFile, String alias, char[] password, char[] keyPass) {
        try {
            // keyStoreFile = "keystores/root1.jks"
            ClassPathResource resource = new ClassPathResource(keyStoreFile);
            KeyStore keyStore = KeyStore.getInstance("JKS");

            try (InputStream is = resource.getInputStream()) {
                keyStore.load(is, password);
            }

            Certificate cert = keyStore.getCertificate(alias);
            if (cert == null) {
                throw new RuntimeException("CA certificate not found in keystore");
            }

            PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, keyPass);

            X500Name issuerName = new JcaX509CertificateHolder((X509Certificate) cert).getSubject();
            return new Issuer(privateKey, cert.getPublicKey(), issuerName);

        } catch (Exception e) {
            throw new RuntimeException("Greška pri učitavanju keystore-a: " + e.getMessage(), e);
        }
    }




    /**
     * Ucitava sertifikat is KS fajla
     */
    public java.security.cert.Certificate readCertificate(String keystoreFileName, String keystorePassword, String alias) throws Exception {
        // Učitaj keystore iz resources foldera
        ClassPathResource resource = new ClassPathResource(keystoreFileName);
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (InputStream is = resource.getInputStream()) {
            keyStore.load(is, keystorePassword.toCharArray());
        }

        java.security.cert.Certificate cert = keyStore.getCertificate(alias);
        if (cert == null) {
            throw new RuntimeException("Certificate with alias " + alias + " not found in keystore");
        }
        return cert;
    }


    /**
     * Ucitava privatni kljuc is KS fajla
     */
    public PrivateKey readPrivateKey(String keyStoreFile, String keyStorePass, String alias, String pass) {
        try {
            //kreiramo instancu KeyStore
            KeyStore ks = KeyStore.getInstance("JKS", "SUN");
            //ucitavamo podatke
            BufferedInputStream in = new BufferedInputStream(new FileInputStream(keyStoreFile));
            ks.load(in, keyStorePass.toCharArray());

            if(ks.isKeyEntry(alias)) {
                PrivateKey pk = (PrivateKey) ks.getKey(alias, pass.toCharArray());
                return pk;
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    public void downloadCertificate(Certificate certificate) {
        try (FileOutputStream fos = new FileOutputStream("example_certificate.cer")) {
            fos.write(certificate.getEncoded());
        } catch (FileNotFoundException | CertificateEncodingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


}
