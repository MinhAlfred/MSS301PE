package exe2.mssapp.msbrand_se181556.repository;


import exe2.mssapp.msbrand_se181556.model.BlindBoxes;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BlindBoxesRepository extends JpaRepository<BlindBoxes, Integer> {
}
