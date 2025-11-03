package exe2.mssapp.msblindbox_se181556.controller;

import exe2.mssapp.msblindbox_se181556.dto.BlindBoxRequest;
import exe2.mssapp.msblindbox_se181556.service.BlindBoxService;
import exe2.mssapp.msblindbox_se181556.util.ApiResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/blindboxes")
@RequiredArgsConstructor
public class Controller {
    private final BlindBoxService blindBoxService;
    @GetMapping("/all")
    public ApiResponse<?> getAll(){
        return ApiResponse.ok(blindBoxService.getAll());
    }
    @PostMapping("/create")
    public ApiResponse<?> create(@RequestBody @Valid BlindBoxRequest request,
                                 @RequestHeader(value = "X-USER-ROLE", required = false) String role
    ){
        if (!role.equals("1")) {
            return ApiResponse.error("Access denied: ADMIN only");
        }
        return ApiResponse.ok("Blind box created successfully",blindBoxService.create(request));
    }
    @DeleteMapping("/delete/{id}")
    public ApiResponse<?> delete(@RequestHeader(value = "X-USER-ROLE", required = false) String role,@PathVariable Integer id){
        if (!role.equals("1")) {
            return ApiResponse.error("Access denied: ADMIN only");
        }
        blindBoxService.deleteById(id);
        return ApiResponse.ok("Blind box deleted successfully");
    }
    @PutMapping("/update/{id}")
    public ApiResponse<?> update(@RequestHeader(value = "X-USER-ROLE", required = false) String role,@PathVariable Integer id, @RequestBody @Valid BlindBoxRequest request){
        if (!role.equals("1")) {
            return ApiResponse.error("Access denied: ADMIN only");
        }
        return ApiResponse.ok("Blind box updated successfully",blindBoxService.update(id, request));
    }
    @GetMapping("/categories" )
    public ApiResponse<?> getAllCategory() {
        return ApiResponse.ok(blindBoxService.getAllCategory());
    }
}
