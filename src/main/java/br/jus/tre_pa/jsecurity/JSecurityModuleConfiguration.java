package br.jus.tre_pa.jsecurity;

import org.springframework.boot.autoconfigure.AutoConfigurationPackage;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(basePackages = "br.jus.tre_pa.jsecurity")
@AutoConfigurationPackage
public class JSecurityModuleConfiguration {

}
