package br.jus.tre_pa.jsecurity.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Getter;
import lombok.Setter;

@Configuration
@ConfigurationProperties(prefix = "keycloak")
@Getter
@Setter
public class KeycloakProperties  {

	private String authServerUrl;

	private String realm;

	@Value("${keycloak.credentials.secret}")
	private String secret;

	@Value("${keycloak.resource}")
	private String clientId;
	
	private String baseUrl;
	
}
