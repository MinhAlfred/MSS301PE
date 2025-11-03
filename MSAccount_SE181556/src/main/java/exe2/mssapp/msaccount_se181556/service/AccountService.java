package exe2.mssapp.msaccount_se181556.service;

import exe2.mssapp.msaccount_se181556.dto.LoginRequest;
import exe2.mssapp.msaccount_se181556.dto.LoginResponse;

public interface AccountService {
    LoginResponse login(LoginRequest request);
}
