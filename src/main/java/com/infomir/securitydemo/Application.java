package com.infomir.securitydemo;

import com.infomir.securitydemo.auth.JwtCore;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@Setter
public class Application {

	public JwtCore jwtCore;

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

}
