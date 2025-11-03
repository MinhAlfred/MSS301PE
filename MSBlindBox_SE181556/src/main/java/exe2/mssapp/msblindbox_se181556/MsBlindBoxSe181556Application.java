package exe2.mssapp.msblindbox_se181556;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.cloud.openfeign.FeignClient;

@SpringBootApplication
@EnableFeignClients
public class MsBlindBoxSe181556Application {

	public static void main(String[] args) {
		SpringApplication.run(MsBlindBoxSe181556Application.class, args);
	}

}
