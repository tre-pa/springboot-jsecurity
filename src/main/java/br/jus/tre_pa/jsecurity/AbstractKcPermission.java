package br.jus.tre_pa.jsecurity;

import java.util.Set;

import org.keycloak.representations.idm.authorization.ResourcePermissionRepresentation;

import com.google.common.collect.Sets;

public abstract class AbstractKcPermission extends AbstractKcArtifact<ResourcePermissionRepresentation> {

	protected Set<String> policies(String...policies) {
		return Sets.newHashSet(policies);
	}
	
	protected Set<String> resources(String...resources) {
		return Sets.newHashSet(resources);
	}
	
}
