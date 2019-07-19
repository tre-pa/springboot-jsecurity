package br.jus.tre_pa.jsecurity.impl;

import java.util.Collection;
import java.util.Objects;

import javax.ws.rs.ProcessingException;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import br.jus.tre_pa.jsecurity.AbstractAggregatePolicy;
import br.jus.tre_pa.jsecurity.AbstractAuthzScope;
import br.jus.tre_pa.jsecurity.AbstractClient;
import br.jus.tre_pa.jsecurity.AbstractClientPolicy;
import br.jus.tre_pa.jsecurity.AbstractGroupPolicy;
import br.jus.tre_pa.jsecurity.AbstractJsPolicy;
import br.jus.tre_pa.jsecurity.AbstractPermission;
import br.jus.tre_pa.jsecurity.AbstractRealm;
import br.jus.tre_pa.jsecurity.AbstractResource;
import br.jus.tre_pa.jsecurity.AbstractRolePolicy;
import br.jus.tre_pa.jsecurity.AbstractRulePolicy;
import br.jus.tre_pa.jsecurity.AbstractTimePolicy;
import br.jus.tre_pa.jsecurity.AbstractUser;
import br.jus.tre_pa.jsecurity.AbstractUserPolicy;
import br.jus.tre_pa.jsecurity.config.SecurityProperties;
import br.jus.tre_pa.jsecurity.exception.JSecurityException;
import br.jus.tre_pa.jsecurity.service.KcService;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class KcServiceImpl implements KcService {

	@Autowired
	private Keycloak keycloak;

	@Autowired
	private SecurityProperties kcProperties;

	/**
	 * Lista com todos os realms.
	 */
	@Autowired
	private Collection<AbstractRealm> realms;

	/**
	 * Lista com todos os clients.
	 */
	@Autowired
	private Collection<AbstractClient> clients;

	/**
	 * Lista com todos os resources.
	 */
	@Autowired(required = false)
	private Collection<AbstractResource> resources;

	/**
	 * Lista com todos authzScopes.
	 */
	@Autowired(required = false)
	private Collection<AbstractAuthzScope> authzScopes;

	/**
	 * Lista com todos os Aggregate Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractAggregatePolicy> aggregatePolcies;

	/**
	 * Lista com todos Client Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractClientPolicy> clientPolicies;

	/**
	 * Lista com todos os Group Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractGroupPolicy> groupPolicies;

	/**
	 * Lista com todos os Js Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractJsPolicy> jsPolicies;

	/**
	 * Lista com todos os Role Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractRolePolicy> rolePolicies;

	/**
	 * Lista com todos os Rule Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractRulePolicy> rulePolicies;

	/**
	 * Lista com todos os Time Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractTimePolicy> timePolicies;

	/**
	 * Lista com todos os User Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractUserPolicy> userPolicies;

	/**
	 * Lista com todas as Permissions.
	 */
	@Autowired(required = false)
	private Collection<AbstractPermission> permissions;

	/**
	 * Lista com todos os usuários.
	 */
	@Autowired(required = false)
	private Collection<AbstractUser> users;

	@EventListener(ContextRefreshedEvent.class)
	protected void register() {
		try {
			log.info("Iniciando registro da aplicação no Keycloak");
			registerRealms();
			registerClients();
			registerUsers();
			registerAuthScopes();
			registerResources();

			log.info("Policies");
			registerRolePolicies();
			registerGroupPolicies();
			registerClientPolicies();
			registerJsPolicies();
			registerRulePolicies();
			registerTimePolicies();
			registerUserPolicies();
			registerAggregatePolicies();
			log.info("Permissions");
			registerPermissions();
		} catch (ProcessingException e) {
			throw new JSecurityException(String.format("Erro ao conectar ao Keycloak em: %s", kcProperties.getAuthServerUrl()));
		}
	}

	/*
	 * Registra os realms da aplicação (Classes que extendem AbstractKcRealm).
	 */
	private void registerRealms() {
		log.info("* Realms ");
		if (Objects.nonNull(realms)) {
			for (AbstractRealm kcrealm : realms) {
				RealmRepresentation realmRepresentation = new RealmRepresentation();
				kcrealm.configure(realmRepresentation);
				this.register(realmRepresentation);
			}
		}
	}

	@Override
	public void register(RealmRepresentation representation) {
		if (!hasRealm()) {
			Assert.hasText(representation.getRealm(), "O atributo 'realm' do realm deve ser definido.");
			keycloak.realms().create(representation);
			log.info("\t Realm '{}' criado com sucesso.", kcProperties.getRealm());
			return;
		}
		log.info("Realm '{}' já existe.", kcProperties.getRealm());
	}

	/*
	 * Registra os clients da aplicação (Classes que extendem AbstractKcClient).
	 */
	private void registerClients() {
		log.info("* Clients ");
		if (Objects.nonNull(clients)) {
			for (AbstractClient kcClient : clients) {
				ClientRepresentation representation = new ClientRepresentation();
				kcClient.configure(representation);
				this.register(representation);
				// Verifica se o recurso de authorization está habilitado para o client.
				if (Objects.nonNull(representation.getAuthorizationServicesEnabled())) {
					// Remove o resource default gerado com o client.
					deleteDefaultResource();
					log.debug("Resource 'Default Resource' removido do client ({}).", kcClient.getClass().getName());
					// Remove a policy default gerada com o client.
					deleteDefaultPolicy();
					log.debug("Role Policy 'Default Policy' removida do client ({}).", kcClient.getClass().getName());
				}
				if (Objects.nonNull(kcClient.roles())) {
					// @formatter:off
					kcClient.roles().stream()
						.map(role -> new RoleRepresentation(role, role, false))
						.forEach(role -> getClient().roles().create(role));
					// @formatter:on
				}
			}
		}
	}

	@Override
	public void register(ClientRepresentation representation) {
		Assert.hasText(representation.getClientId(), String.format("O atributo 'clientId' do client (%s) deve ser definido.", representation.getClass().getName()));
		if (!hasClient(representation.getClientId())) {
			keycloak.realm(kcProperties.getRealm()).clients().create(representation);
			log.info("\t Client '{}' registrado com sucesso.", representation.getClientId());
			return;
		}
		log.info("Client '{}' já existe.", kcProperties.getClientId());
	}

	private void registerAuthScopes() {
		log.info("* Authorization Scopes");
		if (Objects.nonNull(authzScopes)) {
			for (AbstractAuthzScope authScope : authzScopes) {
				ScopeRepresentation representation = new ScopeRepresentation();
				authScope.configure(representation);
				this.register(representation);
			}
		}
	}

	@Override
	public void register(ScopeRepresentation representation) {
		Assert.hasText(representation.getName(), String.format("O atributo 'name' do scope (%s) deve ser definido.", representation.getClass().getName()));
		getClient().authorization().scopes().create(representation);
		log.info("\t Scope '{}' registrado com sucesso.", representation.getName());
	}

	private void registerResources() {
		log.info("* Resources");
		if (Objects.nonNull(resources)) {
			for (AbstractResource resource : resources) {
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
		getClient().authorization().resources().create(representation);
		log.info("\t Resource '{}' registrado com sucesso.", representation.getName());
	}

	private void registerClientPolicies() {
		if (Objects.nonNull(clientPolicies)) {
			for (AbstractClientPolicy policy : clientPolicies) {
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
		getClient().authorization().policies().client().create(representation);
		log.info("\t Client Policy '{}' registrado com sucesso.", representation.getName());
	}

	private void registerGroupPolicies() {
		if (Objects.nonNull(groupPolicies)) {
			for (AbstractGroupPolicy policy : groupPolicies) {
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
		getClient().authorization().policies().group().create(representation);
		log.info("\t Group Policy '{}' registrado com sucesso.", representation.getName());
	}

	private void registerJsPolicies() {
		if (Objects.nonNull(jsPolicies)) {
			for (AbstractJsPolicy policy : jsPolicies) {
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
		getClient().authorization().policies().js().create(representation);
		log.info("\t Js Policy '{}' registrado com sucesso.", representation.getName());
	}

	private void registerRolePolicies() {
		if (Objects.nonNull(rolePolicies)) {
			for (AbstractRolePolicy policy : rolePolicies) {
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
		getClient().authorization().policies().role().create(representation);
		log.info("\t Role Policy '{}' registrada com sucesso.", representation.getName());
	}

	private void registerRulePolicies() {
		if (Objects.nonNull(rulePolicies)) {
			for (AbstractRulePolicy policy : rulePolicies) {
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
		getClient().authorization().policies().rule().create(representation);
		log.info("\t Rule Policy '{}' registrado com sucesso.", representation.getName());
	}

	private void registerTimePolicies() {
		if (Objects.nonNull(timePolicies)) {
			for (AbstractTimePolicy policy : timePolicies) {
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
		getClient().authorization().policies().time().create(representation);
		log.info("\t Time Policy '{}' registrado com sucesso.", representation.getName());
	}

	private void registerUserPolicies() {
		if (Objects.nonNull(userPolicies)) {
			for (AbstractUserPolicy policy : userPolicies) {
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
		getClient().authorization().policies().user().create(representation);
		log.info("\t User Policy '{}' registrado com sucesso.", representation.getName());
	}

	private void registerAggregatePolicies() {
		if (Objects.nonNull(aggregatePolcies)) {
			for (AbstractAggregatePolicy policy : aggregatePolcies) {
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
		getClient().authorization().policies().aggregate().create(representation);
		log.info("Aggregate Policy '{}' registrada com sucesso.", representation.getName());
	}

	private void registerPermissions() {
		log.info("* Permissions ");
		if (Objects.nonNull(permissions)) {
			for (AbstractPermission permission : permissions) {
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
		getClient().authorization().permissions().resource().create(representation);
		log.info("\t Permission '{}' registrado com sucesso.", representation.getName());
	}

	private void registerUsers() {
		log.info("* Users");
		if (Objects.nonNull(users)) {
			for (AbstractUser user : users) {
				UserRepresentation representation = new UserRepresentation();
				user.configure(representation);
				this.register(representation);
			}
		}
	}

	/*
	 * 
	 */
	@Override
	public void register(UserRepresentation representation) {
		Assert.hasText(representation.getUsername(), "O atributo 'username' é obrigatório.");
		Assert.hasText(representation.getEmail(), "O atributo 'email' é obrigatório.");
		keycloak.realm(kcProperties.getRealm()).users().create(representation);
		log.info("\t Usuário '{}' registrado com sucesso.", representation.getUsername());
	}

	private ClientResource getClient() {
		// @formatter:off
		return  keycloak.realm(kcProperties.getRealm()).clients().findByClientId(kcProperties.getClientId()).stream()
				.map(client-> keycloak.realm(kcProperties.getRealm()).clients().get(client.getId()))
				.findFirst()
				.orElseThrow(() -> new IllegalArgumentException(String.format("Erro ao encontrar client '%s'", kcProperties.getClientId() )));
		// @formatter:on
	}

	private boolean hasRealm() {
		return keycloak.realms().findAll().stream().anyMatch(r -> r.getRealm().equals(kcProperties.getRealm()));
	}

	private boolean hasClient(String clientId) {
		// @formatter:off
		return  keycloak.realm(kcProperties.getRealm()).clients().findByClientId(clientId).stream()
				.map(client-> keycloak.realm(kcProperties.getRealm()).clients().get(client.getId()))
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
