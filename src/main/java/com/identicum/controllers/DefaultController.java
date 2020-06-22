package com.identicum.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class DefaultController {
	
	private static final Logger logger = LoggerFactory.getLogger(DefaultController.class);

	@Value("${spring.security.oauth2.client.registration.google.client-id}" )
	private String clientId;

	@GetMapping({"/", "/home"})
	public String home(Model model) {
		logger.debug("ClientId: {}", this.clientId);
		model.addAttribute("clientId", this.clientId);
		return "/home";
	}

	@RequestMapping(value = "/user", method = { RequestMethod.GET, RequestMethod.POST })
	public String user(Model model, @AuthenticationPrincipal OidcUser principal ) {

		try {
			logger.debug("Principal: " + new ObjectMapper().writeValueAsString(principal));
		} catch(JsonProcessingException jpe) {
			logger.error("Error found: " + jpe.getMessage());
		}
		model.addAttribute("name", principal.getName());
		model.addAttribute("claims", principal.getClaims());

		return "/user";
	}

	@GetMapping("/about")
	public String about() {
		return "/about";
	}

}
