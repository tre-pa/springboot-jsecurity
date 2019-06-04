package br.jus.tre_pa.jsecurity.impl;

import java.util.Collection;
import java.util.Objects;

import javax.ws.rs.ProcessingException;

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
import br.jus.tre_pa.jsecurity.config.KeycloakProperties;
import br.jus.tre_pa.jsecurity.exception.JSecurityException;
import br.jus.tre_pa.jsecurity.service.KcService;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class KcServiceImpl implements KcService {

	@Autowired
	private Keycloak keycloak;

	@Autowired
	private KeycloakProperties kcProperties;

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
		try {
			log.info("Iniciando registro da aplicação no Keycloak");
			this.registerRealms();
			this.registerClients();
			this.registerAuthScopes();
			this.registerResources();

			log.info("Policies");
			this.registerRolePolicies();
			this.registerGroupPolicies();
			this.registerClientPolicies();
			this.registerJsPolicies();
			this.registerRulePolicies();
			this.registerTimePolicies();
			this.registerUserPolicies();
			this.registerAggregatePolicies();
			log.info("Permissions");
			this.registerPermissions();
		} catch (ProcessingException e) {
			throw new JSecurityException("Erro ao conectar ao Keycloak. " + e.getMessage());
		}
	}

	/*
	 * Registra os realms da aplicação (Classes que extendem AbstractKcRealm).
	 */
	private void registerRealms() {
		if (Objects.nonNull(this.realms)) {
			for (AbstractKcRealm kcrealm : this.realms) {
				RealmRepresentation realmRepresentation = new RealmRepresentation();
				kcrealm.configure(realmRepresentation);
				this.register(realmRepresentation);
			}
		}
	}

	@Override
	public void register(RealmRepresentation representation) {
		if (!this.hasRealm()) {
			Assert.hasText(representation.getRealm(), "O atributo 'realm' do realm deve ser definido.");
			this.keycloak.realms().create(representation);
			log.info("Realm '{}' criado com sucesso.", this.kcProperties.getRealm());
			return;
		}
		log.info("Realm '{}' já existe.", this.kcProperties.getRealm());
	}

	/*
	 * Registra os clients da aplicação (Classes que extendem AbstractKcClient).
	 */
	private void registerClients() {
		if (Objects.nonNull(this.clients)) {
			for (AbstractKcClient kcClient : this.clients) {
				ClientRepresentation representation = new ClientRepresentation();
				kcClient.configure(representation);
				this.deleteDefaultResource();
				log.info("Resource 'Default Resource' removido do client ({}).", kcClient.getClass().getName());
				this.deleteDefaultPolicy();
				log.info("Role Policy 'Default Policy' removida do client ({}).", kcClient.getClass().getName());

			}
		}
	}

	@Override
	public void register(ClientRepresentation representation) {
		if (!this.hasClient()) {
			Assert.hasText(representation.getClientId(), String.format("O atributo 'clientId' do client (%s) deve ser definido.", representation.getClass().getName()));
			Assert.notEmpty(representation.getRedirectUris(), String.format("O atributo 'redirectUris' do client (%s) deve ser definido.", representation.getClass().getName()));
			this.keycloak.realm(this.kcProperties.getRealm()).clients().create(representation);
			log.info("Client '{}' registrado com sucesso.", representation.getClientId());
			return;
		}
		log.info("Client '{}' já existe.", this.kcProperties.getRealm());
	}

	private void registerAuthScopes() {
		log.info("Scopes");
		if (Objects.nonNull(this.authzScopes)) {
			for (AbstractKcAuthzScope authScope : this.authzScopes) {
				ScopeRepresentation representation = new ScopeRepresentation();
				authScope.configure(representation);
				this.register(representation);
			}
		}
	}

	@Override
	public void register(ScopeRepresentation representation) {
		Assert.hasText(representation.getName(), String.format("O atributo 'name' do scope (%s) deve ser definido.", representation.getClass().getName()));
		this.getClient().authorization().scopes().create(representation);
		log.info("Scope '{}' registrado com sucesso.", representation.getName());
	}

	private void registerResources() {
		log.info("Resources");
		if (Objects.nonNull(this.resources)) {
			for (AbstractKcResource resource : this.resources) {
				ResourceRepresentation representation = new ResourceRepresentation();
				resource.configure(representation);
				this.register(representation);
			}
		}
	}

	@Override
	public void register(ResourceRepresentation representation) {
		Assert.hasText(representation.getName(), "O atributo 'name' do resource deve ser definido.");
		Assert.notEmpty(representation.getScopes(), "O atributo 'scopes' do resource deve ser definido.");

		this.getClient().authorization().resources().create(representation);
		log.info("Resource '{}' registrado com sucesso.", representation.getName());
	}

	private void registerClientPolicies() {
		if (Objects.nonNull(this.clientPolicies)) {
			for (AbstractKcClientPolicy policy : this.clientPolicies) {
				ClientPolicyRepresentation representation = new ClientPolicyRepresentation();
				policy.configure(representation);
				this.register(representation);
			}
		}
	}

	/**
	 * Método registrador de Client Policy.
	 * 
	 * @param policy
	 */
	@Override
	public void register(ClientPolicyRepresentation representation) {
		this.getClient().authorization().policies().client().create(representation);
		log.info("Client Policy '{}' registrado com sucesso.", representation.getName());
	}

	private void registerGroupPolicies() {
		if (Objects.nonNull(this.groupPolicies)) {
			for (AbstractKcGroupPolicy policy : this.groupPolicies) {
				GroupPolicyRepresentation representation = new GroupPolicyRepresentation();
				policy.configure(representation);
				this.register(representation);
			}
		}
	}

	/**
	 * Método registrador de Group Policy.
	 * 
	 * @param policy
	 */
	@Override
	public void register(GroupPolicyRepresentation representation) {
		this.getClient().authorization().policies().group().create(representation);
		log.info("Group Policy '{}' registrado com sucesso.", representation.getName());
	}

	private void registerJsPolicies() {
		if (Objects.nonNull(this.jsPolicies)) {
			for (AbstractKcJsPolicy policy : this.jsPolicies) {
				JSPolicyRepresentation representation = new JSPolicyRepresentation();
				policy.configure(representation);
				this.register(representation);
			}
		}
	}

	/**
	 * Método registrador de Js Policy.
	 * 
	 * @param rolePolicy
	 */
	@Override
	public void register(JSPolicyRepresentation representation) {
		this.getClient().authorization().policies().js().create(representation);
		log.info("Js Policy '{}' registrado com sucesso.", representation.getName());
	}

	private void registerRolePolicies() {
		if (Objects.nonNull(this.rolePolicies)) {
			for (AbstractKcRolePolicy policy : this.rolePolicies) {
				RolePolicyRepresentation representation = new RolePolicyRepresentation();
				policy.configure(representation);
				this.register(representation);
			}
		}
	}

	/**
	 * Método registrador de Role Policy.
	 * 
	 * @param policy
	 */
	@Override
	public void register(RolePolicyRepresentation representation) {
		this.getClient().authorization().policies().role().create(representation);
		log.info("Role Policy '{}' registrada com sucesso.", representation.getName());
	}

	private void registerRulePolicies() {
		if (Objects.nonNull(this.rulePolicies)) {
			for (AbstractKcRulePolicy policy : this.rulePolicies) {
				RulePolicyRepresentation representation = new RulePolicyRepresentation();
				policy.configure(representation);
				this.register(representation);
			}
		}
	}

	/**
	 * Método registrador de Rule Policy.
	 * 
	 * @param rolePolicy
	 */
	@Override
	public void register(RulePolicyRepresentation representation) {
		this.getClient().authorization().policies().rule().create(representation);
		log.info("Rule Policy '{}' registrado com sucesso.", representation.getName());
	}

	private void registerTimePolicies() {
		if (Objects.nonNull(this.timePolicies)) {
			for (AbstractKcTimePolicy policy : this.timePolicies) {
				TimePolicyRepresentation representation = new TimePolicyRepresentation();
				policy.configure(representation);
				this.register(representation);
			}
		}
	}

	/**
	 * Método registrador de Time Policy.
	 * 
	 * @param rolePolicy
	 */
	@Override
	public void register(TimePolicyRepresentation representation) {
		this.getClient().authorization().policies().time().create(representation);
		log.info("Time Policy '{}' registrado com sucesso.", representation.getName());
	}

	private void registerUserPolicies() {
		if (Objects.nonNull(this.userPolicies)) {
			for (AbstractKcUserPolicy policy : this.userPolicies) {
				UserPolicyRepresentation representation = new UserPolicyRepresentation();
				policy.configure(representation);
				this.register(representation);
			}
		}
	}

	/**
	 * Método registrador de User Policy.
	 * 
	 * @param rolePolicy
	 */
	@Override
	public void register(UserPolicyRepresentation representation) {
		this.getClient().authorization().policies().user().create(representation);
		log.info("User Policy '{}' registrado com sucesso.", representation.getName());
	}

	private void registerPermissions() {
		if (Objects.nonNull(this.permissions)) {
			for(AbstractKcPermission permission: this.permissions) {
				ResourcePermissionRepresentation representation = new ResourcePermissionRepresentation();
				permission.configure(representation);
				this.register(representation);
			}
		}
	}

	/**
	 * Método registraro de Permission.
	 * 
	 * @param permission
	 */
	@Override
	public void register(ResourcePermissionRepresentation representation) {
		this.getClient().authorization().permissions().resource().create(representation);
		log.info("Permission '{}' registrado com sucesso.", representation.getName());
	}

	private void registerAggregatePolicies() {
		if (Objects.nonNull(this.aggregatePolcies)) {
			for (AbstractKcAggregatePolicy policy : this.aggregatePolcies) {
				AggregatePolicyRepresentation representation = new AggregatePolicyRepresentation();
				policy.configure(representation);
				this.register(representation);
			}
		}
	}

	/**
	 * Método registrador de Aggragate Policy.
	 * 
	 * @param policy
	 */
	@Override
	public void register(AggregatePolicyRepresentation representation) {
		Assert.hasText(representation.getName(), "O atributo 'name' da aggregate policy deve ser definido.");
		Assert.notEmpty(representation.getPolicies(), "o atributo 'policies' da agregate policy deve ser definido.");
		this.getClient().authorization().policies().aggregate().create(representation);
		log.info("Aggregate Policy '{}' registrada com sucesso.", representation.getName());
	}

	private ClientResource getClient() {
		// @formatter:off
		return  this.keycloak.realm(this.kcProperties.getRealm()).clients().findByClientId(this.kcProperties.getClientId()).stream()
				.map(client-> this.keycloak.realm(this.kcProperties.getRealm()).clients().get(client.getId()))
				.findFirst()
				.orElseThrow(() -> new IllegalArgumentException(String.format("Erro ao encontrar client '%s'", this.kcProperties.getClientId() )));
		// @formatter:on
	}

	private boolean hasRealm() {
		return this.keycloak.realms().findAll().stream().anyMatch(r -> r.getRealm().equals(this.kcProperties.getRealm()));
	}

	private boolean hasClient() {
		// @formatter:off
		return  this.keycloak.realm(this.kcProperties.getRealm()).clients().findByClientId(this.kcProperties.getClientId()).stream()
				.map(client-> this.keycloak.realm(this.kcProperties.getRealm()).clients().get(client.getId()))
				.findFirst()
				.isPresent();
		// @formatter:on
	}

	private void deleteDefaultResource() {
		// @formatter:off
		this.getClient().authorization().resources().resources().stream()
			.filter(p -> p.getName().equals("Default Resource"))
			.findAny()
			.ifPresent(p -> this.getClient().authorization().resources().resource(p.getId()).remove());
		// @formatter:on
	}

	private void deleteDefaultPolicy() {
		// @formatter:off
		this.getClient().authorization().policies().policies().stream()
			.filter(p -> p.getName().equals("Default Policy"))
			.findAny()
			.ifPresent(p -> this.getClient().authorization().policies().policy(p.getId()).remove());
		// @formatter:on
	}

}
