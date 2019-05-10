package br.jus.tre_pa.jsecurity.base;

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

}
