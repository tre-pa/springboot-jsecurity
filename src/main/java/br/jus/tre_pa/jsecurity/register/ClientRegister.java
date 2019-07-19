package br.jus.tre_pa.jsecurity.register;

import java.util.Collection;
import java.util.Objects;

import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import br.jus.tre_pa.jsecurity.AbstractClientConfiguration;
import br.jus.tre_pa.jsecurity.JSecurityRegister;
import br.jus.tre_pa.jsecurity.service.SecurityService;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class ClientRegister implements JSecurityRegister {

	@Autowired
	private SecurityService securityService;

	/**
	 * Lista com todos os clients.
	 */
	@Autowired
	private Collection<AbstractClientConfiguration> clients;

	@Override
	public void register() {
		log.info("-- Client --");
		if (Objects.nonNull(clients)) {
			for (AbstractClientConfiguration kcClient : clients) {
				ClientRepresentation representation = new ClientRepresentation();
				kcClient.configure(representation);
				securityService.register(representation);
				// Verifica se o recurso de authorization está habilitado para o client.
				if (Objects.nonNull(representation.getAuthorizationServicesEnabled())) {
					// Remove o resource default gerado com o client.
					deleteDefaultResource();
					// Remove a policy default gerada com o client.
					deleteDefaultPolicy();
				}
				if (Objects.nonNull(kcClient.roles())) {
					// @formatter:off
					kcClient.roles().stream()
						.map(role -> new RoleRepresentation(role, role, false))
						.forEach(role -> securityService.getClientResource().roles().create(role));
					// @formatter:on
				}
			}
		}
	}

	private void deleteDefaultResource() {
		// @formatter:off
		securityService.getClientResource().authorization().resources().resources().stream()
			.filter(p -> p.getName().equals("Default Resource"))
			.findAny()
			.ifPresent(p -> securityService.getClientResource().authorization().resources().resource(p.getId()).remove());
		// @formatter:on
	}

	private void deleteDefaultPolicy() {
		// @formatter:off
		securityService.getClientResource().authorization().policies().policies().stream()
			.filter(p -> p.getName().equals("Default Policy"))
			.findAny()
			.ifPresent(p -> securityService.getClientResource().authorization().policies().policy(p.getId()).remove());
		// @formatter:on
	}

}
