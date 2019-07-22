package br.jus.tre_pa.jsecurity.register;

import java.util.Collection;
import java.util.Objects;

import org.keycloak.representations.idm.authorization.JSPolicyRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import br.jus.tre_pa.jsecurity.AbstractJsPolicyConfiguration;
import br.jus.tre_pa.jsecurity.JSecurityRegister;
import br.jus.tre_pa.jsecurity.service.SecurityService;

@Component
public class JSPolicyRegister implements JSecurityRegister {

	@Autowired
	private SecurityService securityService;

	/**
	 * Lista com todos os Js Policies.
	 */
	@Autowired(required = false)
	private Collection<AbstractJsPolicyConfiguration> jsPolicies;

	@Override
	public void register() {
		if (Objects.nonNull(jsPolicies)) {
			for (AbstractJsPolicyConfiguration policy : jsPolicies) {
				JSPolicyRepresentation representation = new JSPolicyRepresentation();
				policy.configure(representation);
				securityService.register(representation);
			}
		}
	}

}
