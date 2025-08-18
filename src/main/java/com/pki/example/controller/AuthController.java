package com.pki.example.controller;

import com.pki.example.dto.JwtResponse;
import com.pki.example.dto.LoginRequest;
import com.pki.example.dto.UserDTO;
import com.pki.example.model.User;
import com.pki.example.service.RecaptchaService;
import com.pki.example.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@CrossOrigin(origins = "http://localhost:4200")
@RestController
@RequestMapping(value ="/api/users", produces = MediaType.APPLICATION_JSON_VALUE)

public class AuthController {
    @Autowired
    private UserService userService;

    @Autowired
    private RecaptchaService recaptchaService;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody UserDTO userDto) {
        return userService.register(userDto);
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        return userService.login(request.getEmail(), request.getPassword());
    }


    @GetMapping("/activate/{token}")
    public ResponseEntity<?> activateUser(@PathVariable String token) {
        return userService.activateUser(token);
    }


    @GetMapping("/role/{id}")
    public Integer getRole(@PathVariable Integer id){
        Integer role = userService.getRole(id);
        return role;
    }



}
