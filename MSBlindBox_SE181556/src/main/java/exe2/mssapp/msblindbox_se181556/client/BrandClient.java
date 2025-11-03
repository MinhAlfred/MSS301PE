package exe2.mssapp.msblindbox_se181556.client;

import exe2.mssapp.msblindbox_se181556.dto.BlindBoxRequest;
import exe2.mssapp.msblindbox_se181556.util.ApiResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;

@FeignClient(name = "msbrand", url = "http://brand-service:8082/api/brands")
public interface BrandClient {
    @GetMapping("/name")
    ApiResponse<String> getBrandName(@RequestParam("id") Integer id);
    @PostMapping("/create")
    ApiResponse<?> create(@RequestBody BlindBoxRequest request);
    @DeleteMapping("/delete/{id}")
    ApiResponse<?> delete(@PathVariable("id") Integer id);
    @PutMapping("/update/{id}")
    ApiResponse<?> update(@PathVariable("id") Integer id, @RequestBody BlindBoxRequest request);
}
