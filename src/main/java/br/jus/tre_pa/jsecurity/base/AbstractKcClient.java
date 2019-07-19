package br.jus.tre_pa.jsecurity.base;

import java.util.List;

import org.keycloak.representations.idm.ClientRepresentation;

import lombok.Getter;

/**
 * Classe de representação de um CLIENT.
 * 
 * @author jcruz
 *
 */
@Getter
public abstract class AbstractKcClient extends AbstractKcArtifact<ClientRepresentation> {

	/**
	 * Retorna as roles que serão adcionadas ao client.
	 * 
	 * @return
	 */
	public List<String> roles() {
		return null;
	}
}
