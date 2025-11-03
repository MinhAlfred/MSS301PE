package exe2.mssapp.msbrand_se181556.controller;

import exe2.mssapp.msbrand_se181556.dto.BlindBoxRequest;
import exe2.mssapp.msbrand_se181556.service.BlindBoxService;
import exe2.mssapp.msbrand_se181556.util.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/brands")
@RequiredArgsConstructor
public class Controller {
    private final BlindBoxService blindBoxService;
    @GetMapping("/name")
    public ApiResponse<String> getBrandName(@RequestParam Integer id) {
        String name = blindBoxService.getBlindBoxNameById(id);
        return ApiResponse.ok(name);
    }
    @PostMapping("/create")
    public ApiResponse<?> create(@RequestBody BlindBoxRequest request){
        blindBoxService.create(request);
        return ApiResponse.ok("Blind box created successfully");
    }

    @DeleteMapping("/delete/{id}")
    public ApiResponse<?> delete(@PathVariable Integer id){
        blindBoxService.deleteById(id);
        return ApiResponse.ok("Blind box deleted successfully");
    }
    @PutMapping("/update/{id}")
    public ApiResponse<?> update(@PathVariable Integer id, @RequestBody BlindBoxRequest request){
        blindBoxService.update(id, request);
        return ApiResponse.ok("Blind box updated successfully");
    }
    @GetMapping("/all")
    public ApiResponse<?> getAll() {
        return ApiResponse.ok(blindBoxService.getAll());
    }
}
