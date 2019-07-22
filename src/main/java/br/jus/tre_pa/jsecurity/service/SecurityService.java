package br.jus.tre_pa.jsecurity.service;

import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
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

import br.jus.tre_pa.jsecurity.config.SecurityProperties;

/**
 * Classe com os serviços para manipulação do Keycloak.
 * 
 * @author jcruz
 *
 */
public interface SecurityService {

	/**
	 * Método registrador de Realm.
	 * 
	 * @param representation {@link RealmRepresentation}
	 */
	boolean register(RealmRepresentation representation);

	/**
	 * Método registrador do Client.
	 * 
	 * @param representation {@link ClientRepresentation}
	 */
	boolean register(ClientRepresentation representation);

	/**
	 * Método registrador do AuthzScope.
	 * 
	 * @param authScope ScopeRepresentation {@link ScopeRepresentation}
	 */
	boolean register(ScopeRepresentation representation);

	/**
	 * Método registrador de Resource.
	 * 
	 * @param keycloakResource {@link ResourceRepresentation}
	 */
	boolean register(ResourceRepresentation representation);

	/**
	 * Método registrador de Policy do tipo Client.
	 * 
	 * @param representation {@link ClientPolicyRepresentation}
	 */
	boolean register(ClientPolicyRepresentation representation);

	/**
	 * Método registrador de Policy Role.
	 * 
	 * @param representation {@link RolePolicyRepresentation}
	 */
	boolean register(RolePolicyRepresentation representation);

	/**
	 * Método registrador de Policy do tipo Group.
	 * 
	 * @param representation {@link GroupPolicyRepresentation}
	 */
	boolean register(GroupPolicyRepresentation representation);

	/**
	 * Método registrador de Policy do Tipo Javascript.
	 * 
	 * @param representation {@link JSPolicyRepresentation}
	 */
	boolean register(JSPolicyRepresentation representation);

	/**
	 * Método registrador de Policy Rule.
	 * 
	 * @param representation {@link RulePolicyRepresentation}
	 */
	void register(RulePolicyRepresentation representation);

	/**
	 * Método registrador de Policy Time.
	 * 
	 * @param representation {@link TimePolicyRepresentation}
	 */
	void register(TimePolicyRepresentation representation);

	/**
	 * Método registrador de Policy User.
	 * 
	 * @param representation {@link UserPolicyRepresentation}
	 */
	void register(UserPolicyRepresentation representation);

	/**
	 * Método registrador de Policy do tipo Aggregate.
	 * 
	 * @param representation {@link AggregatePolicyRepresentation}
	 */
	void register(AggregatePolicyRepresentation representation);

	/**
	 * Método registrador de Permission.
	 * 
	 * @param representation {@link ResourcePermissionRepresentation}
	 */
	void register(ResourcePermissionRepresentation representation);

	/**
	 * Método registrador de User.
	 * 
	 * @param representation
	 */
	boolean register(UserRepresentation representation);

	/**
	 * Retorna o ClientResource com clientId definido pela properiedade {@link SecurityProperties#getClientId()}
	 * 
	 * @return
	 */
	ClientResource getClientResource();
}
