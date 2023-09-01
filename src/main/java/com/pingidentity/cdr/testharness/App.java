package com.pingidentity.cdr.testharness;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(exclude={org.springframework.boot.autoconfigure.thymeleaf.ThymeleafAutoConfiguration.class})
public class App {

	public static void main(String[] args) throws Throwable {
		Security.addProvider(new BouncyCastleProvider());
		
		SpringApplication.run(App.class, args);
	}

}