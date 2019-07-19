package br.jus.tre_pa.jsecurity.register;

import java.util.Collection;
import java.util.Objects;

import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import br.jus.tre_pa.jsecurity.AbstractUserConfiguration;
import br.jus.tre_pa.jsecurity.JSecurityRegister;
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
				securityService.register(representation);
			}
		}
	}

}
