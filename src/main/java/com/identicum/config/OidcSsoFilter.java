package com.identicum.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Set;

public class OidcSsoFilter extends OncePerRequestFilter {

	private static final String INVALID_ID_TOKEN_ERROR_CODE = "invalid_id_token";
	private static final Logger logger = LoggerFactory.getLogger(OidcSsoFilter.class);
	private JwtDecoderFactory<ClientRegistration> jwtDecoderFactory = new OidcIdTokenDecoderFactory();

	private ClientRegistrationRepository clientRegistrationRepository;

	public OidcSsoFilter(ClientRegistrationRepository clientRegistrationRepository)
	{
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

		String idTokenString = request.getParameter("credential");
		logger.debug("OIDC SSO Filter processing request");
		if (idTokenString == null){
			logger.debug("No idToken found. Continue chain");
			filterChain.doFilter(request, response);
			return;
		}

		logger.debug("Getting google client registration");
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId("google");

		logger.debug("Parsing received id_token");
		JwtDecoder jwtDecoder = this.jwtDecoderFactory.createDecoder(clientRegistration);
		Jwt jwt;
		try {
			jwt = jwtDecoder.decode(idTokenString);
		} catch (JwtException ex) {
			OAuth2Error invalidIdTokenError = new OAuth2Error(INVALID_ID_TOKEN_ERROR_CODE, ex.getMessage(), null);
			throw new OAuth2AuthenticationException(invalidIdTokenError, invalidIdTokenError.toString(), ex);
		}

		OidcIdToken idToken = new OidcIdToken(jwt.getTokenValue(), jwt.getIssuedAt(), jwt.getExpiresAt(), jwt.getClaims());

		logger.debug("Creating userinfo");
		OidcUserInfo userInfo = new OidcUserInfo(jwt.getClaims());

		logger.debug("Setting authorities");
		Set<GrantedAuthority> authorities = new LinkedHashSet<>();
		authorities.add(new OidcUserAuthority(idToken, userInfo));

		String usernameAttribute = clientRegistration.getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
		logger.debug("Username Attribute: {}", usernameAttribute);

		logger.debug("Create OidcUser");
		OidcUser oidcUser = new DefaultOidcUser(authorities, idToken, userInfo, usernameAttribute);

		logger.debug("Create authResult");
		OidcLoginAuthenticationToken authResult = new OidcLoginAuthenticationToken(oidcUser);

		logger.debug("Setting Authentication");
		SecurityContextHolder.getContext().setAuthentication(authResult);
		onSuccessfulAuthentication(request, response, authResult);
		filterChain.doFilter(request, response);
	}

	protected void onSuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authResult) throws IOException {
	}

}
