package com.pki.example.dto;


import com.pki.example.model.User;

public class UserDTO {

    private Integer id;
    private String email;
    private String name;
    private String surname;
    private String password;
    private String confirmPassword;
    private String organization;

    public UserDTO(){

    }
    public UserDTO(Integer id, String email, String name, String surname, String password, String confirmPassword, String organization) {
        this.id = id;
        this.email = email;
        this.name = name;
        this.surname = surname;
        this.password = password;
        this.confirmPassword = confirmPassword;
        this.organization = organization;

    }

    public UserDTO(User user) {
        this.id = user.getId();
        this.email = user.getEmail();
        this.name = user.getName();
        this.surname = user.getSurname();
        this.password = user.getPassword();
        this.confirmPassword = user.getPassword();
        this.organization = user.getOrganization();

    }
    public Integer getId() {
        return id;
    }
    public String getEmail() {
        return email;
    }

    public String getName() {
        return name;
    }
    public String getSurname() {
        return surname;
    }

    public String getPassword() {
        return password;
    }
    public String getConfirmPassword() {
        return confirmPassword;
    }
    public String getOrganization() {return organization;}

}
