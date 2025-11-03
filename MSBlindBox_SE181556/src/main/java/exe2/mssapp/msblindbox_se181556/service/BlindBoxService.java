package exe2.mssapp.msblindbox_se181556.service;

import exe2.mssapp.msblindbox_se181556.dto.BlindBoxRequest;
import exe2.mssapp.msblindbox_se181556.dto.BlindBoxResponse;
import exe2.mssapp.msblindbox_se181556.model.BlindBoxCategories;

import java.util.List;

public interface BlindBoxService {
    BlindBoxResponse create(BlindBoxRequest request);
    BlindBoxResponse getById(Integer id);
    List<BlindBoxResponse> getAll();
    void deleteById(Integer id);
    BlindBoxResponse update(Integer id, BlindBoxRequest request);
    List<BlindBoxCategories> getAllCategory();
}
