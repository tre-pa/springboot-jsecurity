package br.jus.tre_pa.jsecurity.config;

import java.util.concurrent.TimeUnit;

import javax.servlet.http.HttpServletRequest;

import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.beans.factory.annotation.Autowired;
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
public class SecurityConfig {

	@Autowired
	private SecurityProperties kcProperties;

	@Bean
	public Keycloak getKeycloak() {
		// @formatter:off
		return KeycloakBuilder
				.builder()
				.serverUrl(kcProperties.getAuthServerUrl())
				.realm("master")
				.grantType(OAuth2Constants.PASSWORD)
				.clientId("admin-cli")
				.username(kcProperties.getAdmUser())
				.password(kcProperties.getAdmPass())
				.resteasyClient(new ResteasyClientBuilder()
						.connectTimeout(30, TimeUnit.SECONDS)
						.connectionPoolSize(10).build())
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
