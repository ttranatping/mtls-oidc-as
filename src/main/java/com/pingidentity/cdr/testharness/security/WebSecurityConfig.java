package com.pingidentity.cdr.testharness.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	// private Logger log = Logger.getLogger(WebSecurityConfig.class);

	public WebSecurityConfig() {
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.csrf().disable(); // only intended to be run on mobile devices
		http.anonymous();

	}
}