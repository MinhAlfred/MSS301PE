package exe2.mssapp.msaccount_se181556.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class LoginResponse {
    private String token;
    private Integer accountId;
    private String email;
    private int role;
}
