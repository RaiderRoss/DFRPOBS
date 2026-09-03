package za.co.dfraas;

import org.springframework.boot.SpringApplication;

public class TestDfraasBackendApplication {

	public static void main(String[] args) {
		SpringApplication.from(DfraasBackendApplication::main).with(TestcontainersConfiguration.class).run(args);
	}

}
