package br.jus.tre_pa.jsecurity.register;

import java.util.Collection;
import java.util.Objects;

import org.keycloak.representations.idm.authorization.RolePolicyRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import br.jus.tre_pa.jsecurity.AbstractRolePolicyConfiguration;
import br.jus.tre_pa.jsecurity.JSecurityRegister;
import br.jus.tre_pa.jsecurity.service.SecurityService;

@Component
public class RolePolicyRegister implements JSecurityRegister {

	@Autowired
	private SecurityService securityService;

	/**
	 * Lista com todos os Role Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractRolePolicyConfiguration> rolePolicies;

	@Override
	public void register() {
		if (Objects.nonNull(rolePolicies)) {
			for (AbstractRolePolicyConfiguration policy : rolePolicies) {
				RolePolicyRepresentation representation = new RolePolicyRepresentation();
				policy.configure(representation);
				securityService.register(representation);
			}
		}
	}

}
