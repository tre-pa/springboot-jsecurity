package br.jus.tre_pa.jsecurity;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import org.keycloak.representations.idm.authorization.RolePolicyRepresentation;
import org.keycloak.representations.idm.authorization.RolePolicyRepresentation.RoleDefinition;

import com.google.common.collect.Sets;

/**
 * Classe que representa um POLICY ROLE.
 * 
 * @author jcruz
 *
 */
public abstract class AbstractKcRolePolicy extends AbstractKcArtifact<RolePolicyRepresentation> {

	// @formatter:off
	protected Set<RoleDefinition> roles(String...roles) {
		return Sets.newHashSet(Arrays.asList(roles)
				.stream()
				.map(role -> new RoleDefinition(role, true))
				.collect(Collectors.toSet()));
	}
	// @formatter:on

}
