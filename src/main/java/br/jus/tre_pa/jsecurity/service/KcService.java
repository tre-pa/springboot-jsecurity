package br.jus.tre_pa.jsecurity.service;

import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.authorization.AggregatePolicyRepresentation;
import org.keycloak.representations.idm.authorization.ClientPolicyRepresentation;
import org.keycloak.representations.idm.authorization.GroupPolicyRepresentation;
import org.keycloak.representations.idm.authorization.JSPolicyRepresentation;
import org.keycloak.representations.idm.authorization.ResourcePermissionRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.RolePolicyRepresentation;
import org.keycloak.representations.idm.authorization.RulePolicyRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.keycloak.representations.idm.authorization.TimePolicyRepresentation;
import org.keycloak.representations.idm.authorization.UserPolicyRepresentation;

public interface KcService {

	/**
	 * Método registrador de Realm.
	 * 
	 * @param representation RealmRepresentation
	 */
	void register(RealmRepresentation representation);

	/**
	 * Método registrador do Client.
	 * 
	 * @param representation ClientRepresentation
	 */
	void register(ClientRepresentation representation);

	/**
	 * Método registrador do AuthzScope.
	 * 
	 * @param authScope
	 */
	void register(ScopeRepresentation representation);
	
	/**
	 * Método registrador de Resource.
	 * 
	 * @param keycloakResource
	 */
	void register(ResourceRepresentation representation);

	void register(AggregatePolicyRepresentation representation);

	void register(ClientPolicyRepresentation representation);

	void register(GroupPolicyRepresentation representation);

	void register(JSPolicyRepresentation representation);

	void register(RolePolicyRepresentation representation );

	void register(RulePolicyRepresentation representation);

	void register(TimePolicyRepresentation representation);

	void register(UserPolicyRepresentation representation);

	void register(ResourcePermissionRepresentation representation);
}
