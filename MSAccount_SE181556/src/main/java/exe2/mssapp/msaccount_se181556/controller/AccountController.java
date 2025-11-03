package exe2.mssapp.msaccount_se181556.controller;

import exe2.mssapp.msaccount_se181556.dto.LoginRequest;
import exe2.mssapp.msaccount_se181556.dto.LoginResponse;
import exe2.mssapp.msaccount_se181556.service.AccountService;
import exe2.mssapp.msaccount_se181556.util.ApiResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AccountController {
    private final AccountService accountService;

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@RequestBody @Valid LoginRequest request) {
        LoginResponse response = accountService.login(request);
        return ResponseEntity.ok(ApiResponse.ok("Login success", response));
    }
}
