package exe2.mssapp.msaccount_se181556.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "SystemAccounts")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class SystemAccounts {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer accountId;
    @Column(length = 100, nullable = false)
    private String username;
    @Column(length = 255, nullable = false)
    private String password;
    @Column(length = 255, nullable = false)
    private String email;
    private int role;
    private boolean isActive;
}
