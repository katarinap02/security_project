package com.pki.example.dto;

import com.pki.example.model.User;

public class UserLightDTO {
    private Integer id;
    private String email;

    public UserLightDTO() {}

    public UserLightDTO(User user) {
        this.id = user.getId();
        this.email = user.getEmail();
    }

    public Integer getId() { return id; }
    public String getEmail() { return email; }
}

