package br.jus.tre_pa.jsecurity.base;

import org.springframework.beans.factory.annotation.Value;

import lombok.Getter;

/**
 * Classe genérica de um atefato do keycloak.
 * 
 * @author jcruz
 *
 * @param <T>
 */
@Getter
public abstract class AbstractKcArtifact<T> {

	@Value("${keycloak.realm}")
	private String realm;

	@Value("${keycloak.resource}")
	private String clientId;

	@Value("${keycloak.credentials.secret}")
	private String clientSecret;

	public abstract void configure(T representation);

//	public ClientResource getClient() {
//		// @formatter:off
//		return  keycloak.realm(this.realm).clients().findByClientId(this.clientId).stream()
//				.map(cr-> keycloak.realm(this.realm).clients().get(cr.getId()))
//				.findFirst()
//				.orElseThrow(() -> new IllegalArgumentException("Erro ao encontrar client"));
//		// @formatter:on
//	}

//	protected boolean hasRealm() {
//		return keycloak.realms().findAll().stream().anyMatch(r -> r.getRealm().equals(this.realm));
//	}
}
