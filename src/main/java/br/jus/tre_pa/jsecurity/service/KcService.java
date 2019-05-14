package br.jus.tre_pa.jsecurity.service;

import java.util.Collection;
import java.util.Objects;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.ClientResource;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import br.jus.tre_pa.jsecurity.base.AbstractKcAuthzScope;
import br.jus.tre_pa.jsecurity.base.AbstractKcClient;
import br.jus.tre_pa.jsecurity.base.AbstractKcPermission;
import br.jus.tre_pa.jsecurity.base.AbstractKcRealm;
import br.jus.tre_pa.jsecurity.base.AbstractKcResource;
import br.jus.tre_pa.jsecurity.base.policy.AbstractKcAggregatePolicy;
import br.jus.tre_pa.jsecurity.base.policy.AbstractKcClientPolicy;
import br.jus.tre_pa.jsecurity.base.policy.AbstractKcGroupPolicy;
import br.jus.tre_pa.jsecurity.base.policy.AbstractKcJsPolicy;
import br.jus.tre_pa.jsecurity.base.policy.AbstractKcRolePolicy;
import br.jus.tre_pa.jsecurity.base.policy.AbstractKcRulePolicy;
import br.jus.tre_pa.jsecurity.base.policy.AbstractKcTimePolicy;
import br.jus.tre_pa.jsecurity.base.policy.AbstractKcUserPolicy;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class KcService {

	@Autowired
	private Keycloak keycloak;

	@Value("${keycloak.realm}")
	private String realm;

	@Value("${keycloak.resource}")
	private String clientId;

	/**
	 * Lista com todos os realms.
	 */
	@Autowired
	private Collection<AbstractKcRealm> realms;

	/**
	 * Lista com todos os clients.
	 */
	@Autowired
	private Collection<AbstractKcClient> clients;

	/**
	 * Lista com todos os resources.
	 */
	@Autowired(required = false)
	private Collection<AbstractKcResource> resources;

	/**
	 * Lista com todos authzScopes.
	 */
	@Autowired(required = false)
	private Collection<AbstractKcAuthzScope> authzScopes;

	/**
	 * Lista com todos os Aggregate Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractKcAggregatePolicy> aggregatePolcies;

	/**
	 * Lista com todos Client Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractKcClientPolicy> clientPolicies;

	/**
	 * Lista com todos os Group Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractKcGroupPolicy> groupPolicies;

	/**
	 * Lista com todos os Js Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractKcJsPolicy> jsPolicies;

	/**
	 * Lista com todos os Role Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractKcRolePolicy> rolePolicies;

	/**
	 * Lista com todos os Rule Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractKcRulePolicy> rulePolicies;

	/**
	 * Lista com todos os Time Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractKcTimePolicy> timePolicies;

	/**
	 * Lista com todos os User Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractKcUserPolicy> userPolicies;

	/**
	 * Lista com todas as Permissions.
	 */
	@Autowired(required = false)
	private Collection<AbstractKcPermission> permissions;

	@EventListener(ContextRefreshedEvent.class)
	protected void register() {
		log.info("\n\n * Iniciando registro da aplicação no Keycloak\n");
		if (Objects.nonNull(realms)) realms.forEach(this::register);
		log.info("\n\n ** Clients \n");
		if (Objects.nonNull(clients)) clients.forEach(this::register);
		log.info("\n\n ** Scopes \n");
		if (Objects.nonNull(authzScopes)) authzScopes.forEach(this::register);
		log.info("\n\n ** Resources \n");
		if (Objects.nonNull(resources)) resources.forEach(this::register);
		log.info("\n\n ** Policies \n");
		if (Objects.nonNull(rolePolicies)) rolePolicies.forEach(this::register);
		if (Objects.nonNull(groupPolicies)) groupPolicies.forEach(this::register);
		if (Objects.nonNull(clientPolicies)) clientPolicies.forEach(this::register);
		if (Objects.nonNull(jsPolicies)) jsPolicies.forEach(this::register);
		if (Objects.nonNull(rulePolicies)) rulePolicies.forEach(this::register);
		if (Objects.nonNull(timePolicies)) timePolicies.forEach(this::register);
		if (Objects.nonNull(userPolicies)) userPolicies.forEach(this::register);
		if (Objects.nonNull(aggregatePolcies)) aggregatePolcies.forEach(this::register);
		log.info("\n\n ** Permissions \n");
		if (Objects.nonNull(permissions)) permissions.forEach(this::register);
	}

	/**
	 * Método registrador do Realm.
	 * 
	 * @param keycloakRealm
	 */
	public void register(AbstractKcRealm keycloakRealm) {
		if (!hasRealm()) {
			RealmRepresentation realmRepresentation = new RealmRepresentation();
			keycloakRealm.configure(realmRepresentation);
			Assert.hasText(realmRepresentation.getRealm(), "O atributo 'realm' do realm deve ser definido.");
			keycloak.realms().create(realmRepresentation);
			log.info("Realm '{}' criado com sucesso.", this.realm);
			return;
		}
		log.info("Realm '{}' já existe.", this.realm);
	}

	/**
	 * Método registrador do Client.
	 * 
	 * @param keycloakClient
	 */
	public void register(AbstractKcClient keycloakClient) {
		if (!hasClient()) {
			ClientRepresentation representation = new ClientRepresentation();
			keycloakClient.configure(representation);

			Assert.hasText(representation.getClientId(), String.format("O atributo 'clientId' do client (%s) deve ser definido.", keycloakClient.getClass().getName()));
			Assert.hasText(representation.getSecret(), String.format("O atributo 'secret' do client (%s) deve ser definido.", keycloakClient.getClass().getName()));
			Assert.notEmpty(representation.getRedirectUris(), String.format("O atributo 'redirectUris' do client (%s) deve ser definido.", keycloakClient.getClass().getName()));

			keycloak.realm(this.realm).clients().create(representation);
			this.deleteDefaultResource();
			log.info("Resource 'Default Resource' removido do client ({}).", keycloakClient.getClass().getName());
			this.deleteDefaultPolicy();
			log.info("Role Policy 'Default Policy' removida do client ({}).", keycloakClient.getClass().getName());

			log.info("Client '{}' registrado com sucesso.", representation.getClientId());
			return;
		}
		log.info("Client '{}' já existe.", this.realm);
	}

	/**
	 * Método registrador de Resource.
	 * 
	 * @param keycloakResource
	 */
	public void register(AbstractKcResource keycloakResource) {
		ResourceRepresentation representation = new ResourceRepresentation();
		keycloakResource.configure(representation);

		Assert.hasText(representation.getName(), String.format("O atributo 'name' do resource (%s) deve ser definido.", keycloakResource.getClass().getName()));
		Assert.notEmpty(representation.getScopes(), String.format("O atributo 'scopes' do resource (%s) deve ser definido.", keycloakResource.getClass().getName()));

		getClient().authorization().resources().create(representation);
		log.info("Resource '{}' registrado com sucesso.", representation.getName());
	}

	/**
	 * Método registrador do AuthzScope.
	 * 
	 * @param authScope
	 */
	public void register(AbstractKcAuthzScope authScope) {
		ScopeRepresentation representation = new ScopeRepresentation();
		authScope.configure(representation);

		Assert.hasText(representation.getName(), String.format("O atributo 'name' do scope (%s) deve ser definido.", authScope.getClass().getName()));

		this.getClient().authorization().scopes().create(representation);
		log.info("Scope '{}' registrado com sucesso.", representation.getName());
	}

	/**
	 * Método registrador de Aggragate Policy.
	 * 
	 * @param policy
	 */
	public void register(AbstractKcAggregatePolicy policy) {
		AggregatePolicyRepresentation representation = new AggregatePolicyRepresentation();
		policy.configure(representation);

		Assert.hasText(representation.getName(), String.format("O atributo 'name' da aggregate policy (%s) deve ser definido.", policy.getClass().getName()));
		Assert.notEmpty(representation.getPolicies(), String.format("o atributo 'policies' da agregate policy (%s) deve ser definido.", policy.getClass().getName()));

		this.getClient().authorization().policies().aggregate().create(representation);
		log.info("Aggregate Policy '{}' registrada com sucesso.", representation.getName());
	}

	/**
	 * Método registrador de Client Policy.
	 * 
	 * @param policy
	 */
	public void register(AbstractKcClientPolicy policy) {
		ClientPolicyRepresentation representation = new ClientPolicyRepresentation();
		policy.configure(representation);
		this.getClient().authorization().policies().client().create(representation);
		log.info("Client Policy '{}' registrado com sucesso.", representation.getName());
	}

	/**
	 * Método registrador de Group Policy.
	 * 
	 * @param policy
	 */
	public void register(AbstractKcGroupPolicy policy) {
		GroupPolicyRepresentation representation = new GroupPolicyRepresentation();
		policy.configure(representation);
		this.getClient().authorization().policies().group().create(representation);
		log.info("Group Policy '{}' registrado com sucesso.", representation.getName());
	}

	/**
	 * Método registrador de Js Policy.
	 * 
	 * @param rolePolicy
	 */
	public void register(AbstractKcJsPolicy policy) {
		JSPolicyRepresentation representation = new JSPolicyRepresentation();
		policy.configure(representation);
		this.getClient().authorization().policies().js().create(representation);
		log.info("Js Policy '{}' registrado com sucesso.", representation.getName());
	}

	/**
	 * Método registrador de Role Policy.
	 * 
	 * @param policy
	 */
	public void register(AbstractKcRolePolicy policy) {
		RolePolicyRepresentation representation = new RolePolicyRepresentation();
		policy.configure(representation);
		this.getClient().authorization().policies().role().create(representation);
		log.info("Role Policy '{}' registrada com sucesso.", representation.getName());
	}

	/**
	 * Método registrador de Rule Policy.
	 * 
	 * @param rolePolicy
	 */
	public void register(AbstractKcRulePolicy policy) {
		RulePolicyRepresentation representation = new RulePolicyRepresentation();
		policy.configure(representation);
		this.getClient().authorization().policies().rule().create(representation);
		log.info("Rule Policy '{}' registrado com sucesso.", representation.getName());
	}

	/**
	 * Método registrador de Time Policy.
	 * 
	 * @param rolePolicy
	 */
	public void register(AbstractKcTimePolicy policy) {
		TimePolicyRepresentation representation = new TimePolicyRepresentation();
		policy.configure(representation);
		this.getClient().authorization().policies().time().create(representation);
		log.info("Time Policy '{}' registrado com sucesso.", representation.getName());
	}

	/**
	 * Método registrador de User Policy.
	 * 
	 * @param rolePolicy
	 */
	public void register(AbstractKcUserPolicy policy) {
		UserPolicyRepresentation representation = new UserPolicyRepresentation();
		policy.configure(representation);
		this.getClient().authorization().policies().user().create(representation);
		log.info("User Policy '{}' registrado com sucesso.", representation.getName());
	}

	/**
	 * Método registraro de Permission.
	 * 
	 * @param permission
	 */
	public void register(AbstractKcPermission permission) {
		ResourcePermissionRepresentation representation = new ResourcePermissionRepresentation();
		permission.configure(representation);
		getClient().authorization().permissions().resource().create(representation);
		log.info("Permission '{}' registrado com sucesso.", representation.getName());
	}

	private ClientResource getClient() {
		// @formatter:off
		return  keycloak.realm(this.realm).clients().findByClientId(this.clientId).stream()
				.map(client-> keycloak.realm(this.realm).clients().get(client.getId()))
				.findFirst()
				.orElseThrow(() -> new IllegalArgumentException(String.format("Erro ao encontrar client '%s'", this.clientId )));
		// @formatter:on
	}

	private boolean hasRealm() {
		return keycloak.realms().findAll().stream().anyMatch(r -> r.getRealm().equals(this.realm));
	}

	private boolean hasClient() {
		// @formatter:off
		return  keycloak.realm(this.realm).clients().findByClientId(this.clientId).stream()
				.map(client-> keycloak.realm(this.realm).clients().get(client.getId()))
				.findFirst()
				.isPresent();
		// @formatter:on
	}

	private void deleteDefaultResource() {
		// @formatter:off
		getClient().authorization().resources().resources().stream()
			.filter(p -> p.getName().equals("Default Resource"))
			.findAny()
			.ifPresent(p -> getClient().authorization().resources().resource(p.getId()).remove());
		// @formatter:on
	}

	private void deleteDefaultPolicy() {
		// @formatter:off
		getClient().authorization().policies().policies().stream()
			.filter(p -> p.getName().equals("Default Policy"))
			.findAny()
			.ifPresent(p -> getClient().authorization().policies().policy(p.getId()).remove());
		// @formatter:on
	}

}
