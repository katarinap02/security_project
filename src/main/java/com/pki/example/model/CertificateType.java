package com.pki.example.model;

public enum CertificateType {
    ROOT,
    INTERMEDIATE,
    END_ENTITY;

    public static CertificateType fromString(String text) {
        if (text == null) {
            throw new IllegalArgumentException("Certificate type cannot be null.");
        }

        // Prolazimo kroz sve moguće vrednosti enuma (ROOT, INTERMEDIATE, END_ENTITY)
        for (CertificateType type : CertificateType.values()) {
            if (type.name().equalsIgnoreCase(text.trim())) {
                return type;
            }
        }
        throw new IllegalArgumentException("Unknown certificate type: '" + text + "'. Allowed values are ROOT, INTERMEDIATE, END_ENTITY.");
    }
}
