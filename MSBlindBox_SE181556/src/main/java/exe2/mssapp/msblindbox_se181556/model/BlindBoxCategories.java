package exe2.mssapp.msblindbox_se181556.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "BlindBoxCategories")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class BlindBoxCategories {
    @Id
    @GeneratedValue(strategy = jakarta.persistence.GenerationType.IDENTITY)
    private Integer categoryId;
    private String categoryName;
    @Column(columnDefinition = "TEXT")
    private String description;
    private String rarityLevel;
    private String priceRange;
}
