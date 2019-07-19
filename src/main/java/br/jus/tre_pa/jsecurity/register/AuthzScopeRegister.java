package br.jus.tre_pa.jsecurity.register;

import java.util.Collection;
import java.util.Objects;

import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import br.jus.tre_pa.jsecurity.AbstractAuthzScopeConfiguration;
import br.jus.tre_pa.jsecurity.JSecurityRegister;
import br.jus.tre_pa.jsecurity.service.SecurityService;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class AuthzScopeRegister implements JSecurityRegister {

	@Autowired
	private SecurityService securityService;

	/**
	 * Lista com todos authzScopes.
	 */
	@Autowired(required = false)
	private Collection<AbstractAuthzScopeConfiguration> authzScopes;

	@Override
	public void register() {
		log.info("-- Authorization Scopes --");
		if (Objects.nonNull(authzScopes)) {
			for (AbstractAuthzScopeConfiguration authScope : authzScopes) {
				ScopeRepresentation representation = new ScopeRepresentation();
				authScope.configure(representation);
				securityService.register(representation);
			}
		}
	}

}
