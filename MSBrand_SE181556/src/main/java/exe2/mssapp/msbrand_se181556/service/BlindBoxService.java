package exe2.mssapp.msbrand_se181556.service;


import exe2.mssapp.msbrand_se181556.dto.BlindBoxRequest;
import exe2.mssapp.msbrand_se181556.dto.BlindBoxResponse;
import exe2.mssapp.msbrand_se181556.model.Brand;

import java.util.List;

public interface BlindBoxService {
    void create(BlindBoxRequest request);
    void deleteById(Integer id);
    void update(Integer id, BlindBoxRequest request);
    String getBlindBoxNameById(Integer id);
    List<Brand> getAll();
}
