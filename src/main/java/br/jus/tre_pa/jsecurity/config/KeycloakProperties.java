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

	/**
	 * URL de conexão do keycloak.
	 */
	@Value("${keycloak.auth-server-url}")
	private String authServerUrl;

	/**
	 * Realm padrão da aplicação.
	 */
	@Value("${keycloak.realm}")
	private String realm;

	/**
	 * Secret da aplicação backend.
	 */
	@Value("${keycloak.credentials.secret}")
	private String secret;

	/**
	 * ClientId da aplicação backend.
	 */
	@Value("${keycloak.resource}")
	private String clientId;

	/**
	 * URL base da aplicação.
	 */
	private String baseUrl;

	/**
	 * URIs de redirecionamento da aplicação frontend.
	 */
	@Value("#{'${kc.redirect-uris}'.split(',')}")
	private List<String> redirectUris;

	/**
	 * Usuário administrador do realm master do Keycloak.
	 */
	private String admUser;

	/**
	 * Password do usuário administrador do realm master do Keycloak.
	 */
	private String admPass;

}
