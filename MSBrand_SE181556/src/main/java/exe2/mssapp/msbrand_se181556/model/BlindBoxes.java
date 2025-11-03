package exe2.mssapp.msbrand_se181556.model;

import jakarta.persistence.*;
import lombok.*;

import java.math.BigDecimal;
import java.time.LocalDate;

@Entity
@Table(name = "BlindBoxes")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class BlindBoxes {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer blindBoxId;
    private String name;
    @ManyToOne(fetch = FetchType.LAZY)
    private Brand brand;
    private int categoryId;
    @Column(precision = 10, scale = 2)
    private BigDecimal price;
    private LocalDate realeaseDate;
    private int stock;
}
