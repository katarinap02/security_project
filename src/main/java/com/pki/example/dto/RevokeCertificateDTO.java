package com.pki.example.dto;

import com.pki.example.model.RevocationReason;

public class RevokeCertificateDTO {
    private String serialNumber;
    private RevocationReason reason;
    private String comment;

    public RevokeCertificateDTO() {}

    public RevokeCertificateDTO(String serialNumber, RevocationReason reason, String comment) {
        this.serialNumber = serialNumber;
        this.reason = reason;
        this.comment = comment;
    }

    // Getters and Setters
    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public RevocationReason getReason() {
        return reason;
    }

    public void setReason(RevocationReason reason) {
        this.reason = reason;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }
}
