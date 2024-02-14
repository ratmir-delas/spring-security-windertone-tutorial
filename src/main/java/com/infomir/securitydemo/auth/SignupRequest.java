package com.infomir.securitydemo.auth;

import lombok.Data;

@Data
public class SignupRequest {
    private String username;
    private String password;
    private String email;
    private String role;
}
