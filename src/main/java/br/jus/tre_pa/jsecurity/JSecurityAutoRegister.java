package br.jus.tre_pa.jsecurity;

import javax.ws.rs.ProcessingException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import br.jus.tre_pa.jsecurity.config.SecurityProperties;
import br.jus.tre_pa.jsecurity.exception.JSecurityException;
import br.jus.tre_pa.jsecurity.register.AggregatePolicyRegister;
import br.jus.tre_pa.jsecurity.register.ClientPolicyRegister;
import br.jus.tre_pa.jsecurity.register.ClientRegister;
import br.jus.tre_pa.jsecurity.register.GroupPolicyRegister;
import br.jus.tre_pa.jsecurity.register.JSPolicyRegister;
import br.jus.tre_pa.jsecurity.register.PermissionRegister;
import br.jus.tre_pa.jsecurity.register.RealmRegister;
import br.jus.tre_pa.jsecurity.register.ResourceRegister;
import br.jus.tre_pa.jsecurity.register.RolePolicyRegister;
import br.jus.tre_pa.jsecurity.register.RulePolicyRegister;
import br.jus.tre_pa.jsecurity.register.TimePolicyRegister;
import br.jus.tre_pa.jsecurity.register.UserPolicyRegister;
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
			applicationContext.getBean(ResourceRegister.class).register();
			applicationContext.getBean(RolePolicyRegister.class).register();
			applicationContext.getBean(ClientPolicyRegister.class).register();
			applicationContext.getBean(RulePolicyRegister.class).register();
			applicationContext.getBean(JSPolicyRegister.class).register();
			applicationContext.getBean(GroupPolicyRegister.class).register();
			applicationContext.getBean(TimePolicyRegister.class).register();
			applicationContext.getBean(UserPolicyRegister.class).register();
			applicationContext.getBean(AggregatePolicyRegister.class).register();
			applicationContext.getBean(PermissionRegister.class).register();
		} catch (ProcessingException e) {
			throw new JSecurityException(String.format("Erro ao conectar ao Keycloak em: %s", securityProperties.getAuthServerUrl()));
		}
	}
}
