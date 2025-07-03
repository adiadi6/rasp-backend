package com.rasp.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages = {"com.rasp.app.controller","controller", "platform.webservice.map", "platform.webservice.controller.base", "com.rasp.app.config", "platform.defined.account.controller", "com.rasp.app.service"})

public class Application {
	public static void main(String[] args) {
		Registry.register();
		SpringApplication.run(Application.class, args);
	}
}
