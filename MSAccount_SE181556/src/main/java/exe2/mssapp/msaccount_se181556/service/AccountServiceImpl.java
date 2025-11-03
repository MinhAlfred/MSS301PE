package exe2.mssapp.msaccount_se181556.service;

import exe2.mssapp.msaccount_se181556.dto.LoginRequest;
import exe2.mssapp.msaccount_se181556.dto.LoginResponse;
import exe2.mssapp.msaccount_se181556.model.SystemAccounts;
import exe2.mssapp.msaccount_se181556.repository.AccountRepository;
import exe2.mssapp.msaccount_se181556.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AccountServiceImpl implements AccountService {
    private final AccountRepository accountRepository;
    private final JwtUtil jwtUtil;
    @Override
    public LoginResponse login(LoginRequest request) {
        SystemAccounts account = accountRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Account not found"));
        if (!account.isActive()) {
            throw new RuntimeException("Account is inactive");
        }
        if (!request.getPassword().equals(account.getPassword())) {
            throw new RuntimeException("Invalid password");
        }
        String token = jwtUtil.generateToken(account);

        return new LoginResponse(
                token,
                account.getAccountId(),
                account.getEmail(),
                account.getRole()
        );
    }
}
