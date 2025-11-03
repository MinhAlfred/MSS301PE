package exe2.mssapp.msbrand_se181556.util;


import exe2.mssapp.msbrand_se181556.model.BlindBoxes;
import exe2.mssapp.msbrand_se181556.model.Brand;
import exe2.mssapp.msbrand_se181556.repository.BlindBoxesRepository;
import exe2.mssapp.msbrand_se181556.repository.BrandRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.time.LocalDate;

@Component
@RequiredArgsConstructor
public class DataSeeder implements CommandLineRunner {

    private final BlindBoxesRepository blindBoxesRepository;
    private final BrandRepository brandRepository;
    @Override
    public void run(String... args) {
        Brand brand1 = new Brand(null, "POP MART", "China");
        Brand brand2 = new Brand(null, "Funko", "USA");
        Brand brand3 = new Brand(null, "Kidrobot", "USA");
        if (brandRepository.count() == 0) {
            brandRepository.save(brand1);
            brandRepository.save(brand2);
            brandRepository.save(brand3);
            System.out.println("Sample data inserted!");
        } else {
            System.out.println("Data already initialized. Skipping seeding.");
        }
        if( blindBoxesRepository.count() == 0){
            blindBoxesRepository.save(new BlindBoxes(null, "Mystic Creatures Series 1",brand1,1,new BigDecimal("29.99"), LocalDate.now(), 150));
            blindBoxesRepository.save(new BlindBoxes(null, "Cyberpunk Warriors", brand2,2, new BigDecimal("49.99"), LocalDate.of(2023, 11, 20), 75));
            blindBoxesRepository.save(new BlindBoxes(null, "Fantasy Legends", brand1,1, new BigDecimal("19.99"), LocalDate.of(2024, 2, 10), 200));
            blindBoxesRepository.save(new BlindBoxes(null, "Space Explorers",  brand3,3, new BigDecimal("59.99"), LocalDate.of(2023, 12, 5), 50));
            blindBoxesRepository.save(new BlindBoxes(null, "Neon Anime Stars",  brand1,4, new BigDecimal("99.99"), LocalDate.of(2024, 3, 1), 25));
            blindBoxesRepository.save(new BlindBoxes(null, "Retro Arcade Heroes",  brand2,2, new BigDecimal("24.99"), LocalDate.of(2024, 1, 30), 180));
            blindBoxesRepository.save(new BlindBoxes(null, "Mythical Beasts Collection", brand3,1, new BigDecimal("54.99"), LocalDate.of(2023, 10, 10), 60));
            blindBoxesRepository.save(new BlindBoxes(null, "Superhero Legends",  brand2,3, new BigDecimal("39.99"), LocalDate.of(2024, 2, 20), 120));
            blindBoxesRepository.save(new BlindBoxes(null, "Steampunk Adventurers",  brand3,2, new BigDecimal("69.99"), LocalDate.of(2023, 12, 15), 40));
            blindBoxesRepository.save(new BlindBoxes(null, "Kawaii Anime Pets",  brand1,4, new BigDecimal("14.99"), LocalDate.of(2024, 3, 5), 250));
            System.out.println("Sample blind box data inserted!");
        } else {
            System.out.println("Blind box data already initialized. Skipping seeding.");
        }
    }
}
