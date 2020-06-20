package com.identicum.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.csrf().disable()
				.addFilterBefore(new OidcSsoFilter(clientRegistrationRepository), OAuth2LoginAuthenticationFilter.class)
				.authorizeRequests(authorizeRequest -> authorizeRequest
						.antMatchers("/", "/webjars/**", "/css/**", "/favicon.*", "/imgs/**").permitAll()
						.anyRequest().authenticated())
				.oauth2Login(oauthLogin -> oauthLogin
						.userInfoEndpoint()
						.oidcUserService(new OidcUserService()));
	}

}
