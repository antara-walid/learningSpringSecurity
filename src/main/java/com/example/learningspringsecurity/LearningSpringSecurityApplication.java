package com.example.learningspringsecurity;

import com.example.learningspringsecurity.sec.entity.AppRole;
import com.example.learningspringsecurity.sec.entity.AppUser;
import com.example.learningspringsecurity.sec.service.AccountService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class LearningSpringSecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(LearningSpringSecurityApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder()
	{
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner commandLineRunner(AccountService accountService)
	{
		return args -> {
			// ADD ROLES
			accountService.addNewRole(new AppRole(null,"USER"));
			accountService.addNewRole(new AppRole(null,"ADMIN"));
			accountService.addNewRole(new AppRole(null,"CUSTOMER_MANAGER"));
			accountService.addNewRole(new AppRole(null,"PRODUCT_MANAGER"));
			accountService.addNewRole(new AppRole(null,"BILLS_MANAGER"));


			// ADD USERS
			accountService.addNewUser(new AppUser(null,"user1","123",new ArrayList<>()));
			accountService.addNewUser(new AppUser(null,"admin","123",new ArrayList<>()));
			accountService.addNewUser(new AppUser(null,"user2","123",new ArrayList<>()));
			accountService.addNewUser(new AppUser(null,"user3","123",new ArrayList<>()));
			accountService.addNewUser(new AppUser(null,"user4","123",new ArrayList<>()));

			//DELEGATE ROLES TO USERS
			accountService.addRoleToUser("user1","USER");
			accountService.addRoleToUser("admin","USER");
			accountService.addRoleToUser("admin","ADMIN");
			accountService.addRoleToUser("user2","USER");
			accountService.addRoleToUser("user2","CUSTOMER_MANAGER");
			accountService.addRoleToUser("user2","USER");
			accountService.addRoleToUser("user3","PRODUCT_MANAGER");
			accountService.addRoleToUser("user3","USER");
			accountService.addRoleToUser("user3","BILLS_MANAGER");

		};
	}

}
