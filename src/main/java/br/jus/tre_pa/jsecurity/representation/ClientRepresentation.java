package br.jus.tre_pa.jsecurity.representation;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class ClientRepresentation extends org.keycloak.representations.idm.ClientRepresentation {

	private String[] roles;

}
