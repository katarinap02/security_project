package com.pki.example.dto;

public class IssueCSRRequest {
    private String csrContent;
    private IssuerCertificateDTO dto;

    public String getCsrContent() {
        return csrContent;
    }

    public void setCsrContent(String csrContent) {
        this.csrContent = csrContent;
    }

    public IssuerCertificateDTO getDto() {
        return dto;
    }

    public void setDto(IssuerCertificateDTO dto) {
        this.dto = dto;
    }
}
