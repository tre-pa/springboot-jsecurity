package br.jus.tre_pa.jsecurity.config;

import javax.servlet.http.HttpServletRequest;

import org.keycloak.KeycloakSecurityContext;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Classe de configuração do Keycloak.
 * 
 * @author jcruz
 *
 */
@Configuration
public class KeycloakConfig {

	@Autowired
	private KeycloakProperties kcProperties;

	@Value("${keycloak.adm-user:admin}")
	private String admuser;

	@Value("${keycloak.adm-pass:admin}")
	private String admpass;

	@Bean
	public Keycloak getKeycloak() {
		// @formatter:off
		return KeycloakBuilder
				.builder()
				.serverUrl(this.kcProperties.getAuthServerUrl())
				.realm("master")
				.grantType(OAuth2Constants.PASSWORD)
				.clientId("admin-cli")
				.username(this.admuser)
				.password(this.admpass)
				.build();
		// @formatter:on
	}

	/**
	 * Retorna o contexto de segurança do Keycloak.
	 * 
	 * @return
	 */
	@Bean
	@Scope(scopeName = WebApplicationContext.SCOPE_REQUEST, proxyMode = ScopedProxyMode.TARGET_CLASS)
	public KeycloakSecurityContext accessToken() {
		HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
		return (KeycloakSecurityContext) request.getAttribute(KeycloakSecurityContext.class.getName());
	}
}
