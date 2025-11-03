package exe2.mssapp.msblindbox_se181556.repository;

import exe2.mssapp.msblindbox_se181556.model.BlindBoxCategories;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface BlindBoxCategoriesRepository extends JpaRepository<BlindBoxCategories,Integer> {

}
