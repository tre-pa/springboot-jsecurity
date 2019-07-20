package br.jus.tre_pa.jsecurity.register;

import java.util.Collection;
import java.util.Objects;

import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import br.jus.tre_pa.jsecurity.AbstractResourceConfiguration;
import br.jus.tre_pa.jsecurity.JSecurityRegister;
import br.jus.tre_pa.jsecurity.service.SecurityService;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class ResourceRegister implements JSecurityRegister {

	@Autowired
	private SecurityService securityService;

	/**
	 * Lista com todos os resources.
	 */
	@Autowired(required = false)
	private Collection<AbstractResourceConfiguration> resources;

	@Override
	public void register() {
		log.info("-- Resources --");
		if (Objects.nonNull(resources)) {
			for (AbstractResourceConfiguration resource : resources) {
				ResourceRepresentation representation = new ResourceRepresentation();
				resource.configure(representation);
				securityService.register(representation);
			}
		}
	}

}
