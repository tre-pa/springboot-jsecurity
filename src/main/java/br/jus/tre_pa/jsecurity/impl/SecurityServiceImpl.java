package br.jus.tre_pa.jsecurity.impl;

import java.util.Collection;
import java.util.Objects;

import org.keycloak.admin.client.Keycloak;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import br.jus.tre_pa.jsecurity.AbstractAggregatePolicyConfiguration;
import br.jus.tre_pa.jsecurity.AbstractPermissionConfiguration;
import br.jus.tre_pa.jsecurity.AbstractRulePolicyConfiguration;
import br.jus.tre_pa.jsecurity.AbstractTimePolicyConfiguration;
import br.jus.tre_pa.jsecurity.AbstractUserPolicyConfiguration;
import br.jus.tre_pa.jsecurity.config.SecurityProperties;
import br.jus.tre_pa.jsecurity.service.SecurityService;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class SecurityServiceImpl implements SecurityService {

	@Autowired
	private Keycloak keycloak;

	@Autowired
	private SecurityProperties kcProperties;

	/**
	 * Lista com todos os Aggregate Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractAggregatePolicyConfiguration> aggregatePolcies;

	/**
	 * Lista com todos os Rule Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractRulePolicyConfiguration> rulePolicies;

	/**
	 * Lista com todos os Time Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractTimePolicyConfiguration> timePolicies;

	/**
	 * Lista com todos os User Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractUserPolicyConfiguration> userPolicies;

	/**
	 * Lista com todas as Permissions.
	 */
	@Autowired(required = false)
	private Collection<AbstractPermissionConfiguration> permissions;

	@Override
	public boolean register(RealmRepresentation representation) {
		if (!hasRealm()) {
			Assert.hasText(representation.getRealm(), "O atributo 'realm' do realm deve ser definido.");
			keycloak.realms().create(representation);
			log.info("\t Realm '{}' criado com sucesso.", kcProperties.getRealm());
			return true;
		}
		log.info("\t Realm '{}' já existe.", kcProperties.getRealm());
		return false;
	}

	@Override
	public boolean register(ClientRepresentation representation) {
		Assert.hasText(representation.getClientId(), String.format("O atributo 'clientId' do client (%s) deve ser definido.", representation.getClass().getName()));
		if (!hasClient(representation.getClientId())) {
			keycloak.realm(kcProperties.getRealm()).clients().create(representation);
			// Verifica se o recurso de authorization está habilitado para o client.
			if (Objects.nonNull(representation.getAuthorizationServicesEnabled())) {
				// Remove o resource default gerado com o client. @formatter:off
				getClientResource().authorization().resources().resources().stream()
					.filter(p -> p.getName().equals("Default Resource"))
					.findAny()
					.ifPresent(p -> getClientResource().authorization().resources().resource(p.getId()).remove());
				// @formatter:on

				// Remove a policy default gerada com o client. @formatter:off
				getClientResource().authorization().policies().policies().stream()
					.filter(p -> p.getName().equals("Default Policy"))
					.findAny()
					.ifPresent(p -> getClientResource().authorization().policies().policy(p.getId()).remove());
				// @formatter:on
			}
			log.info("\t Client '{}' registrado com sucesso.", representation.getClientId());
			return true;
		}
		log.info("\t Client '{}' já existe.", representation.getClientId());
		return false;
	}

	@Override
	public boolean register(ScopeRepresentation representation) {
		Assert.hasText(representation.getName(), String.format("O atributo 'name' do scope (%s) deve ser definido.", representation.getClass().getName()));
		// Verifica a existência do scope.
		if (!hasScope(representation.getName())) {
			getClientResource().authorization().scopes().create(representation);
			log.info("\t Scope '{}' registrado com sucesso.", representation.getName());
			return true;
		}
		log.info("\t Scope '{}' já existe.", representation.getName());
		return false;
	}

	// TODO Verificar a existência dos Scopes antes de criar o Resource.
	@Override
	public boolean register(ResourceRepresentation representation) {
		Assert.hasText(representation.getName(), "O atributo 'name' do resource deve ser definido.");
		Assert.notEmpty(representation.getScopes(), "O atributo 'scopes' do resource deve ser definido.");
		if (!hasResource(representation.getName())) {
			getClientResource().authorization().resources().create(representation);
			log.info("\t Resource '{}' registrado com sucesso.", representation.getName());
			return true;
		}
		log.info("\t Resource '{}' já existe.", representation.getName());
		return false;
	}

	// TODO Exibir nome da classe no erro de assert.
	@Override
	public boolean register(ClientPolicyRepresentation representation) {
		Assert.hasText(representation.getName(), "O atributo 'name' da ClientPolicy '{}' é obrigatório.");
		Assert.notEmpty(representation.getClients(), "É necessário adicionar pelo menos 1 client a policy.");
		// Verifica se o policy existe
		if (!hasPolicy(representation.getName())) {
			getClientResource().authorization().policies().client().create(representation);
			log.info("\t Client Policy '{}' registrado com sucesso.", representation.getName());
			return true;
		}
		log.info("\t Client Policy '{}' já existe.");
		return false;
	}

	@Override
	public boolean register(RolePolicyRepresentation representation) {
		Assert.hasText(representation.getName(), "O atributo 'name' da RolePolicy é obrigatório.");
		// Verifica se o role existe ou no client ou no realm.
		if (hasClientRole(representation.getName()) || hasRealmRole(representation.getName())) {
			getClientResource().authorization().policies().role().create(representation);
			log.info("\t Role Policy '{}' registrada com sucesso.", representation.getName());
			return true;
		}
		log.info("Role '{}' inexistente. ", representation.getName());
		return false;
	}

	/**
	 * Método registrador de Group Policy.
	 * 
	 * @param policy
	 */
	@Override
	public boolean register(GroupPolicyRepresentation representation) {
		Assert.hasLength(representation.getName(), "O atributo 'name' da GrupoPolicy é obrigatório.");
		Assert.notEmpty(representation.getGroups(), String.format("É necessário atribuir pelo menos 1 group a GroupPolicy '%s'.", representation.getName()));

		getClientResource().authorization().policies().group().create(representation);
		log.info("\t Group Policy '{}' registrado com sucesso.", representation.getName());
		return true;
	}

	/**
	 * Método registrador de Js Policy.
	 * 
	 * @param rolePolicy
	 */
	@Override
	public boolean register(JSPolicyRepresentation representation) {
		Assert.hasText(representation.getName(), "O atributo 'name' é obrigatório na JSPolicy.");
		Assert.hasText(representation.getCode(), String.format("O atributo 'code' é obrigatório na JSPolicy '%s'.", representation.getName()));

		getClientResource().authorization().policies().js().create(representation);
		log.info("\t Js Policy '{}' registrado com sucesso.", representation.getName());
		return true;
	}

	private void registerRulePolicies() {
		if (Objects.nonNull(rulePolicies)) {
			for (AbstractRulePolicyConfiguration policy : rulePolicies) {
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
		getClientResource().authorization().policies().rule().create(representation);
		log.info("\t Rule Policy '{}' registrado com sucesso.", representation.getName());
	}

	private void registerTimePolicies() {
		if (Objects.nonNull(timePolicies)) {
			for (AbstractTimePolicyConfiguration policy : timePolicies) {
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
		getClientResource().authorization().policies().time().create(representation);
		log.info("\t Time Policy '{}' registrado com sucesso.", representation.getName());
	}

	private void registerUserPolicies() {
		if (Objects.nonNull(userPolicies)) {
			for (AbstractUserPolicyConfiguration policy : userPolicies) {
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
		getClientResource().authorization().policies().user().create(representation);
		log.info("\t User Policy '{}' registrado com sucesso.", representation.getName());
	}

	private void registerAggregatePolicies() {
		if (Objects.nonNull(aggregatePolcies)) {
			for (AbstractAggregatePolicyConfiguration policy : aggregatePolcies) {
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
		getClientResource().authorization().policies().aggregate().create(representation);
		log.info("Aggregate Policy '{}' registrada com sucesso.", representation.getName());
	}

	private void registerPermissions() {
		log.info("* Permissions ");
		if (Objects.nonNull(permissions)) {
			for (AbstractPermissionConfiguration permission : permissions) {
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
		getClientResource().authorization().permissions().resource().create(representation);
		log.info("\t Permission '{}' registrado com sucesso.", representation.getName());
	}

	/*
	 * 
	 */
	@Override
	public boolean register(UserRepresentation representation) {
		Assert.hasText(representation.getUsername(), "O atributo 'username' é obrigatório.");
		Assert.hasText(representation.getEmail(), "O atributo 'email' é obrigatório.");
		if (!hasUser(representation.getUsername())) {
			keycloak.realm(kcProperties.getRealm()).users().create(representation);
			log.info("\t Usuário '{}' registrado com sucesso.", representation.getUsername());
			return true;
		}
		log.info("\t Usuário '{}' já existe.", representation.getUsername());
		return false;
	}

	@Override
	public ClientResource getClientResource() {
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

	private boolean hasUser(String username) {
		return keycloak.realm(kcProperties.getRealm()).users().search(username).isEmpty() == false;
	}

	private boolean hasScope(String scopeName) {
		return Objects.nonNull(getClientResource().authorization().scopes().findByName(scopeName));
	}

	private boolean hasPolicy(String policyName) {
		return Objects.nonNull(getClientResource().authorization().policies().findByName(policyName));
	}

	private boolean hasResource(String resourceName) {
		return getClientResource().authorization().resources().findByName(resourceName).isEmpty() == false;
	}

	private boolean hasClientRole(String roleName) {
		return Objects.nonNull(getClientResource().roles().get(roleName));
	}

	private boolean hasRealmRole(String roleName) {
		return Objects.nonNull(keycloak.realm(kcProperties.getRealm()).roles().get(roleName));
	}

}
