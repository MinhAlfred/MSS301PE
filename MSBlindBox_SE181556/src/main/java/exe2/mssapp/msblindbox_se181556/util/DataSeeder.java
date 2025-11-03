package exe2.mssapp.msblindbox_se181556.util;

import exe2.mssapp.msblindbox_se181556.model.BlindBoxCategories;
import exe2.mssapp.msblindbox_se181556.model.BlindBoxes;
import exe2.mssapp.msblindbox_se181556.repository.BlindBoxCategoriesRepository;
import exe2.mssapp.msblindbox_se181556.repository.BlindBoxesRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.time.LocalDate;

@Component
@RequiredArgsConstructor
public class DataSeeder implements CommandLineRunner {

    private final BlindBoxesRepository blindBoxesRepository;
    private final BlindBoxCategoriesRepository blindBoxCategoriesRepository;
    @Override
    public void run(String... args) {
        var category1 = new BlindBoxCategories(null, "Fantasy", "Mystical creatures, wizards, and legendary beings.","Common to Ultra Rare","$10 - $60");
        var category2 = new BlindBoxCategories(null, "Gaming", "Blind boxes featuring characters from popular video games.", "Common to Epic", "$25 - $70");
        var category3 = new BlindBoxCategories(null, "Sci-Fi", "Space, futuristic themes, and robotic collectibles.", "Rare to Legendary", "$30 - $80");
        var category4 = new BlindBoxCategories(null, "Anime", "Popular anime characters and themed mystery figures.", "Common to Legendary", "$15 - $100");
        var category5 = new BlindBoxCategories(null, "Steampunk", "Victorian-era inspired mechanical and fantasy figures.", "Rare to Epic", "$100 - $190");
        if( blindBoxCategoriesRepository.count() == 0) {
            blindBoxCategoriesRepository.save(category1);
            blindBoxCategoriesRepository.save(category2);
            blindBoxCategoriesRepository.save(category3);
            blindBoxCategoriesRepository.save(category4);
            blindBoxCategoriesRepository.save(category5);
            System.out.println("Sample data inserted!");
        } else {
            System.out.println("Data already initialized. Skipping seeding.");
        }
        if( blindBoxesRepository.count() == 0){
            blindBoxesRepository.save(new BlindBoxes(null, "Mystic Creatures Series 1",category1,1,new BigDecimal("29.99"), LocalDate.now(), 150));
            blindBoxesRepository.save(new BlindBoxes(null, "Cyberpunk Warriors", category2,2, new BigDecimal("49.99"), LocalDate.of(2023, 11, 20), 75));
            blindBoxesRepository.save(new BlindBoxes(null, "Fantasy Legends", category1,1, new BigDecimal("19.99"), LocalDate.of(2024, 2, 10), 200));
            blindBoxesRepository.save(new BlindBoxes(null, "Space Explorers",  category3,3, new BigDecimal("59.99"), LocalDate.of(2023, 12, 5), 50));
            blindBoxesRepository.save(new BlindBoxes(null, "Neon Anime Stars",  category4,1, new BigDecimal("99.99"), LocalDate.of(2024, 3, 1), 25));
            blindBoxesRepository.save(new BlindBoxes(null, "Retro Arcade Heroes",  category2,2, new BigDecimal("24.99"), LocalDate.of(2024, 1, 30), 180));
            blindBoxesRepository.save(new BlindBoxes(null, "Mythical Beasts Collection", category1,3, new BigDecimal("54.99"), LocalDate.of(2023, 10, 10), 60));
            blindBoxesRepository.save(new BlindBoxes(null, "Superhero Legends",  category3,2, new BigDecimal("39.99"), LocalDate.of(2024, 2, 20), 120));
            blindBoxesRepository.save(new BlindBoxes(null, "Steampunk Adventurers",  category2,3, new BigDecimal("69.99"), LocalDate.of(2023, 12, 15), 40));
            blindBoxesRepository.save(new BlindBoxes(null, "Kawaii Anime Pets",  category4,1, new BigDecimal("14.99"), LocalDate.of(2024, 3, 5), 250));
            System.out.println("Sample blind box data inserted!");
        } else {
            System.out.println("Blind box data already initialized. Skipping seeding.");
        }
    }
}
