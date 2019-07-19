package br.jus.tre_pa.jsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import br.jus.tre_pa.jsecurity.register.ClientRegister;
import br.jus.tre_pa.jsecurity.register.RealmRegister;

/**
 * Classe que realiza o registro automático (inicialização da aplicação) dos arrtefatos no Keycloak.
 * 
 * @author jcruz
 *
 */
@Component
public class JSecurityAutoRegister {

	@Autowired
	private ApplicationContext applicationContext;

	@EventListener(ContextRefreshedEvent.class)
	protected void init() {
		applicationContext.getBean(RealmRegister.class).register();
		applicationContext.getBean(ClientRegister.class).register();
	}
}
