package br.jus.tre_pa.jsecurity.service;

import br.jus.tre_pa.jsecurity.base.AbstractKcAuthzScope;
import br.jus.tre_pa.jsecurity.base.AbstractKcClient;
import br.jus.tre_pa.jsecurity.base.AbstractKcPermission;
import br.jus.tre_pa.jsecurity.base.AbstractKcRealm;
import br.jus.tre_pa.jsecurity.base.AbstractKcResource;
import br.jus.tre_pa.jsecurity.base.policy.AbstractKcAggregatePolicy;
import br.jus.tre_pa.jsecurity.base.policy.AbstractKcClientPolicy;
import br.jus.tre_pa.jsecurity.base.policy.AbstractKcGroupPolicy;
import br.jus.tre_pa.jsecurity.base.policy.AbstractKcJsPolicy;
import br.jus.tre_pa.jsecurity.base.policy.AbstractKcRolePolicy;
import br.jus.tre_pa.jsecurity.base.policy.AbstractKcRulePolicy;
import br.jus.tre_pa.jsecurity.base.policy.AbstractKcTimePolicy;
import br.jus.tre_pa.jsecurity.base.policy.AbstractKcUserPolicy;

public interface KcService {

	void register(AbstractKcRealm keycloakRealm);

	void register(AbstractKcClient keycloakClient);

	void register(AbstractKcResource keycloakResource);

	void register(AbstractKcAuthzScope authScope);

	void register(AbstractKcAggregatePolicy policy);

	void register(AbstractKcClientPolicy policy);

	void register(AbstractKcGroupPolicy policy);

	void register(AbstractKcJsPolicy policy);

	void register(AbstractKcRolePolicy policy);

	void register(AbstractKcRulePolicy policy);

	void register(AbstractKcTimePolicy policy);

	void register(AbstractKcUserPolicy policy);

	void register(AbstractKcPermission permission);
}
