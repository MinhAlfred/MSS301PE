package exe2.mssapp.msblindbox_se181556.dto;

import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.Date;

@Data
public class BlindBoxResponse {
    private Integer blindBoxId;
    private String name;
    private String categoryName;
    private String brandName;
    private BigDecimal price;
    private LocalDate releaseDate;
    private int stock;
}