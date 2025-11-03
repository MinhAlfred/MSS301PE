package exe2.mssapp.msbrand_se181556.dto;

import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDate;

@Data
public class BlindBoxRequest {
    private String name;

    private Integer categoryId;

    private Integer brandId;

    private BigDecimal price;

    private Integer stock;

    private LocalDate releaseDate;
}
