package br.jus.tre_pa.jsecurity;

import org.springframework.beans.factory.annotation.Autowired;

import br.jus.tre_pa.jsecurity.config.KeycloakProperties;
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

	@Autowired
	private KeycloakProperties kcProperties;

	public abstract void configure(T representation);

}
