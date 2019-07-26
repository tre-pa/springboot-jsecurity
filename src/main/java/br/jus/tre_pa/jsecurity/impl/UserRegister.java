package br.jus.tre_pa.jsecurity.impl;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import br.jus.tre_pa.jsecurity.AbstractUserConfiguration;
import br.jus.tre_pa.jsecurity.config.SecurityProperties;
import br.jus.tre_pa.jsecurity.register.JSecurityRegister;
import br.jus.tre_pa.jsecurity.service.SecurityService;
import lombok.extern.slf4j.Slf4j;

/**
 * Classe quer registra os usuários no Keycloak.
 * 
 * @author jcruz
 *
 */
@Component
@Slf4j
public class UserRegister implements JSecurityRegister {

	@Autowired
	private Keycloak keycloak;

	@Autowired
	private SecurityProperties securityProperties;

	@Autowired
	private SecurityService securityService;
	/**
	 * Lista com todos os usuários.
	 */
	@Autowired(required = false)
	private Collection<AbstractUserConfiguration> users;

	@Override
	public void register() {
		log.info("-- Users --");
		if (Objects.nonNull(users)) {
			for (AbstractUserConfiguration user : users) {
				UserRepresentation representation = new UserRepresentation();
				user.configure(representation);
				if (!securityService.register(representation)) {
					ClientRepresentation clientRepresentation = securityService.getClientResource(securityProperties.getClientId()).toRepresentation();
					// Atualiza as roles do usuário para o client.
					addDefaultRoles(representation, clientRepresentation);
				}
			}
		}
	}

	private void addDefaultRoles(UserRepresentation representation, ClientRepresentation clientRepresentation) {
		if (Objects.nonNull(clientRepresentation.getDefaultRoles())) {
			// @formatter:off
			UserResource userResource = keycloak.realm(securityProperties.getRealm()).users().search(representation.getUsername())
				.stream()
				.findFirst()
				.map(userRepresentation -> keycloak.realm(securityProperties.getRealm()).users().get(userRepresentation.getId()))
				.orElseThrow(() -> new IllegalArgumentException(String.format("Erro ao encontrar usuário: ", representation.getUsername())));

			// @formatter:off
			List<RoleRepresentation> roles = userResource.roles().clientLevel(clientRepresentation.getId())
				.listAvailable()
				.stream()
				.filter(roleRepresentation -> Arrays.asList(clientRepresentation.getDefaultRoles()).contains(roleRepresentation.getName()))
				.collect(Collectors.toList());
			// @formatter:on
			if (!roles.isEmpty()) userResource.roles().clientLevel(clientRepresentation.getId()).add(roles);
		}
	}

}
