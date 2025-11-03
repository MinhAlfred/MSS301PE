package exe2.mssapp.msblindbox_se181556.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.Date;

@Entity
@Table(name = "BlindBoxes")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class BlindBoxes {
    @Id
    @GeneratedValue(strategy = jakarta.persistence.GenerationType.IDENTITY)
    private Integer blindBoxId;
    private String name;
    @ManyToOne(fetch = FetchType.LAZY)
    @JsonIgnore
    private BlindBoxCategories category;
    private int brandId;
    @Column(precision = 10, scale = 2)
    private BigDecimal price;
    private LocalDate realeaseDate;
    private int stock;
}
