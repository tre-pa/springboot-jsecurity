package br.jus.tre_pa.jsecurity.register;

import java.util.Collection;
import java.util.Objects;

import org.keycloak.representations.idm.authorization.UserPolicyRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import br.jus.tre_pa.jsecurity.AbstractUserPolicyConfiguration;
import br.jus.tre_pa.jsecurity.JSecurityRegister;
import br.jus.tre_pa.jsecurity.service.SecurityService;

@Component
public class UserPolicyRegister implements JSecurityRegister {

	@Autowired

	private SecurityService securityService;

	/**
	 * Lista com todos os User Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractUserPolicyConfiguration> userPolicies;

	@Override
	public void register() {
		if (Objects.nonNull(userPolicies)) {
			for (AbstractUserPolicyConfiguration policy : userPolicies) {
				UserPolicyRepresentation representation = new UserPolicyRepresentation();
				policy.configure(representation);
				securityService.register(representation);
			}
		}
	}

}
