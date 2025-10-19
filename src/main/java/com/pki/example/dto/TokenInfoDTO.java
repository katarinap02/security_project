package com.pki.example.dto;

import com.pki.example.model.TokenInfo;


public class TokenInfoDTO {
    private String jti;
    private String ipAddress;
    private String userAgent;
    private String lastActivity;

    public TokenInfoDTO(TokenInfo token) {
        this.jti = token.getJti();
        this.ipAddress = token.getIpAddress();
        this.userAgent = token.getUserAgent();
        this.lastActivity = token.getLastActivity().toString(); // ili DateTimeFormatter.ISO_LOCAL_DATE_TIME
    }

    public String getJti() {
        return jti;
    }
    public void setJti(String jti) {
        this.jti = jti;
    }
    public String getIpAddress() {
        return ipAddress;
    }
    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }
    public String getUserAgent() {
        return userAgent;
    }
    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }
    public String getLastActivity() {
        return lastActivity;
    }
    public void setLastActivity(String lastActivity) {
        this.lastActivity = lastActivity;
    }
}
