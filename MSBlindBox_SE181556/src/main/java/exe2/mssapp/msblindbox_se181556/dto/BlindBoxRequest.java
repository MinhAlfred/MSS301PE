package exe2.mssapp.msblindbox_se181556.dto;

import jakarta.validation.constraints.*;
import lombok.Data;
import org.hibernate.validator.constraints.Length;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.Date;
@Data
public class BlindBoxRequest {
    @NotBlank(message = "Name is required")
    @Size(min = 10, message = "Name must be at least 10 characters long")
    private String name;

    @NotNull(message = "Category ID is required")
    private Integer categoryId;

    @NotNull(message = "Brand ID is required")
    private Integer brandId;

    @NotNull(message = "Price is required")
    @DecimalMin(value = "0.0", inclusive = false, message = "Price must be greater than 0")
    private BigDecimal price;

    @NotNull(message = "Stock is required")
    @Min(value = 1, message = "Stock must be at least 1")
    @Max(value = 100, message = "Stock must be at most 100")
    private Integer stock;

    @NotNull(message = "Release date is required")
    private LocalDate releaseDate;
}
