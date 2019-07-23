package br.jus.tre_pa.jsecurity.impl;

import java.util.Collection;
import java.util.Objects;

import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import br.jus.tre_pa.jsecurity.AbstractClientConfiguration;
import br.jus.tre_pa.jsecurity.JSecurityRegister;
import br.jus.tre_pa.jsecurity.service.SecurityService;
import lombok.extern.slf4j.Slf4j;

/**
 * Classe que registra o client no Keycloak.
 * 
 * @author jcruz
 *
 */
@Component
@Slf4j
public class ClientRegister implements JSecurityRegister {

	@Autowired
	private SecurityService securityService;

	/**
	 * Lista com todos os clients.
	 */
	@Autowired
	private Collection<AbstractClientConfiguration> clientsConf;

	@Override
	public void register() {
		log.info("-- Client --");
		if (Objects.nonNull(clientsConf)) {
			for (AbstractClientConfiguration clientConf : clientsConf) {
				ClientRepresentation representation = new ClientRepresentation();
				clientConf.configure(representation);
				if (securityService.register(representation)) {
					if (Objects.nonNull(clientConf.roles())) {
					// @formatter:off
					clientConf.roles().stream()
						.filter(role -> !StringUtils.isEmpty(role))
						.map(role -> new RoleRepresentation(role, role, false))
						.forEach(role -> securityService.getClientResource().roles().create(role));
					// @formatter:on
					}
				}
			}
		}
	}

}
