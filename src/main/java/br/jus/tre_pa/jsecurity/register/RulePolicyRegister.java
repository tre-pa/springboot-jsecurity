package br.jus.tre_pa.jsecurity.register;

import java.util.Collection;
import java.util.Objects;

import org.keycloak.representations.idm.authorization.RulePolicyRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import br.jus.tre_pa.jsecurity.AbstractRulePolicyConfiguration;
import br.jus.tre_pa.jsecurity.JSecurityRegister;
import br.jus.tre_pa.jsecurity.service.SecurityService;

@Component
public class RulePolicyRegister implements JSecurityRegister {

	@Autowired
	private SecurityService securityService;

	/**
	 * Lista com todos os Rule Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractRulePolicyConfiguration> rulePolicies;

	@Override
	public void register() {
		if (Objects.nonNull(rulePolicies)) {
			for (AbstractRulePolicyConfiguration policy : rulePolicies) {
				RulePolicyRepresentation representation = new RulePolicyRepresentation();
				policy.configure(representation);
				securityService.register(representation);
			}
		}
	}

}
