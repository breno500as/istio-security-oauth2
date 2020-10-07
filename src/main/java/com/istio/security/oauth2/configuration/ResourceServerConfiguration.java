package com.istio.security.oauth2.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

@EnableResourceServer
@Configuration
public class ResourceServerConfiguration extends  ResourceServerConfigurerAdapter  {
	
	@Override
	public void configure(HttpSecurity http) throws Exception {
		http
	    .authorizeRequests()
	    .antMatchers("/.well-known/jwks.json").permitAll()
	    .anyRequest().authenticated();
	}

}
