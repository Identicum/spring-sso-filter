package com.identicum.config;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

public class OidcLoginAuthenticationToken extends AbstractAuthenticationToken {

	private OidcUser principal;

	@Override
	public String getName() {
		return this.principal.getFullName();
	}

	public OidcLoginAuthenticationToken(OidcUser principal) {
		super(principal.getAuthorities());
		this.principal = principal;
		this.setAuthenticated(true);
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}
}
