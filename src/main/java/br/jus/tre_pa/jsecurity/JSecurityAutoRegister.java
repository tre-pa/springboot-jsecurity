package br.jus.tre_pa.jsecurity;

import javax.ws.rs.ProcessingException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import br.jus.tre_pa.jsecurity.config.SecurityProperties;
import br.jus.tre_pa.jsecurity.exception.JSecurityException;
import br.jus.tre_pa.jsecurity.register.AuthzScopeRegister;
import br.jus.tre_pa.jsecurity.register.ClientRegister;
import br.jus.tre_pa.jsecurity.register.RealmRegister;
import br.jus.tre_pa.jsecurity.register.UserRegister;
import lombok.extern.slf4j.Slf4j;

/**
 * Classe que realiza o registro automático (inicialização da aplicação) dos arrtefatos no Keycloak.
 * 
 * @author jcruz
 *
 */
@Component
@Slf4j
public class JSecurityAutoRegister {

	@Autowired
	private ApplicationContext applicationContext;

	@Autowired
	private SecurityProperties securityProperties;

	@EventListener(ContextRefreshedEvent.class)
	protected void init() {
		log.info("Iniciando o auto-registro dos artefatos no Keycloak...");
		try {
			applicationContext.getBean(RealmRegister.class).register();
			applicationContext.getBean(ClientRegister.class).register();
			applicationContext.getBean(UserRegister.class).register();
			applicationContext.getBean(AuthzScopeRegister.class).register();
		} catch (ProcessingException e) {
			throw new JSecurityException(String.format("Erro ao conectar ao Keycloak em: %s", securityProperties.getAuthServerUrl()));
		}
	}
}
