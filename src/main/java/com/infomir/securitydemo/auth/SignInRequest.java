package com.infomir.securitydemo.auth;

import lombok.Data;

@Data
public class SignInRequest {
    private String username;
    private String password;
}
