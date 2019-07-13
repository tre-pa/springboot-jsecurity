package br.jus.tre_pa.jsecurity.config;

import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Getter;
import lombok.Setter;

/**
 * Classe de Properties com as propriedades do keycloak. Além das propriedades padrões do keycloak (iniciadas com o prefixo 'keycloak.') é definido o prefixo 'kc' para propriedades
 * customizadas.
 * 
 * @author jcruz
 *
 */
@Configuration
@ConfigurationProperties(prefix = "kc")
@Getter
@Setter
public class KeycloakProperties {

	@Value("${keycloak.auth-server-url}")
	private String authServerUrl;

	@Value("${keycloak.realm}")
	private String realm;

	@Value("${keycloak.credentials.secret}")
	private String secret;

	@Value("${keycloak.resource}")
	private String clientId;

	private String baseUrl;

	@Value("#{'${kc.redirect-uris}'.split(',')}")
	private List<String> redirectUris;

	private String admUser;

	private String admPass;

}
