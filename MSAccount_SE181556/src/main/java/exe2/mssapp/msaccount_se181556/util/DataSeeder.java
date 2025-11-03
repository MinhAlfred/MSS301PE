package exe2.mssapp.msaccount_se181556.util;

import exe2.mssapp.msaccount_se181556.model.SystemAccounts;
import exe2.mssapp.msaccount_se181556.repository.AccountRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class DataSeeder implements CommandLineRunner {

    private final AccountRepository accountRepository;

    @Override
    public void run(String... args) {
        if (accountRepository.count() == 0) {
            accountRepository.save(new SystemAccounts(null, "adminsys",  "@2","admin@blindboxes.vn", 1, true));
            accountRepository.save(new SystemAccounts(null, "johndoe","@2", "john@blindboxes.vn",  4, true));
            accountRepository.save(new SystemAccounts(null, "modmichel", "@2","michel@blindboxes.vn",  2, true));
            accountRepository.save(new SystemAccounts(null, "vanvan","@2", "vanavan@blindboxes.vn",  4, false));
            accountRepository.save(new SystemAccounts(null, "devops","@2", "dev@blindboxes.vn",  3, true));

            System.out.println("Sample accounts inserted!");
        } else {
            System.out.println("Accounts already initialized. Skipping seeding.");
        }
    }
}
