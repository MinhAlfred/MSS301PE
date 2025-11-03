package exe2.mssapp.msaccount_se181556.repository;

import exe2.mssapp.msaccount_se181556.model.SystemAccounts;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
@Repository
public interface AccountRepository extends JpaRepository<SystemAccounts, Integer> {
    Optional<SystemAccounts> findByEmail(String email);
}
