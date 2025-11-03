package exe2.mssapp.msblindbox_se181556.service;

import exe2.mssapp.msblindbox_se181556.client.BrandClient;
import exe2.mssapp.msblindbox_se181556.dto.BlindBoxRequest;
import exe2.mssapp.msblindbox_se181556.dto.BlindBoxResponse;
import exe2.mssapp.msblindbox_se181556.model.BlindBoxCategories;
import exe2.mssapp.msblindbox_se181556.model.BlindBoxes;
import exe2.mssapp.msblindbox_se181556.repository.BlindBoxCategoriesRepository;
import exe2.mssapp.msblindbox_se181556.repository.BlindBoxesRepository;
import exe2.mssapp.msblindbox_se181556.util.ApiResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;
import java.util.Objects;

@Service
@RequiredArgsConstructor
public class BlindBoxServiceImpl implements BlindBoxService{
    private final BlindBoxesRepository blindBoxesRepository;
    private final BlindBoxCategoriesRepository blindBoxCategoriesRepository;
    private final BrandClient brandClient;
    @Override
    public BlindBoxResponse create(BlindBoxRequest request) {
        LocalDate inputDate = request.getReleaseDate();
        LocalDate today = LocalDate.now();
        if (!inputDate.equals(today)) {
            throw new RuntimeException("Release date must be today");
        }
        BlindBoxCategories category = blindBoxCategoriesRepository.findById(request.getCategoryId())
                .orElseThrow(() -> new RuntimeException("Category not found"));
        if(!Objects.equals(request.getReleaseDate(), LocalDate.now())) {
            throw new RuntimeException("Release date must be today");
        }
        BlindBoxes blindBox = BlindBoxes.builder()
                .name(request.getName())
                .category(category)
                .brandId(request.getBrandId())
                .price(request.getPrice())
                .realeaseDate(request.getReleaseDate())
                .stock(request.getStock())
                .build();
        BlindBoxes savedBlindBox = blindBoxesRepository.save(blindBox);
        brandClient.create(request);
        return getById(savedBlindBox.getBlindBoxId());
    }

    @Override
    public BlindBoxResponse getById(Integer id) {
        BlindBoxes blindBox = blindBoxesRepository.findById(id).orElseThrow(
                () -> new RuntimeException("Blind box not found")
        );
        ApiResponse<String> data = brandClient.getBrandName(id);
        String name = data.getData();
        BlindBoxResponse response = new BlindBoxResponse();
        response.setBlindBoxId(blindBox.getBlindBoxId());
        response.setName(blindBox.getName());
        response.setPrice(blindBox.getPrice());
        response.setReleaseDate(blindBox.getRealeaseDate());
        response.setStock(blindBox.getStock());
        response.setCategoryName(blindBox.getCategory().getCategoryName());
        response.setBrandName(name);
        return response;
    }

    @Override
    public List<BlindBoxResponse> getAll() {
        List<BlindBoxes> blindBoxes = blindBoxesRepository.findAll();
        return blindBoxes.stream().map(blindBox -> {
            return getById(blindBox.getBlindBoxId());
        }).toList();
    }

    @Override
    public void deleteById(Integer id) {
        BlindBoxes blindBox = blindBoxesRepository.findById(id).orElseThrow(
                () -> new RuntimeException("Blind box not found")
        );
        blindBoxesRepository.delete(blindBox);
        brandClient.delete(id);
    }

    @Override
    public BlindBoxResponse update(Integer id, BlindBoxRequest request) {
        BlindBoxes blindBox = blindBoxesRepository.findById(id).orElseThrow(
                () -> new RuntimeException("Blind box not found")
        );
        BlindBoxCategories category = blindBoxCategoriesRepository.findById(request.getCategoryId()).orElseThrow(
                () -> new RuntimeException("Category not found"));
        blindBox.setName(request.getName());
        blindBox.setCategory(category);
        blindBox.setBrandId(request.getBrandId());
        blindBox.setPrice(request.getPrice());
        blindBox.setRealeaseDate(request.getReleaseDate());
        blindBox.setStock(request.getStock());
        blindBoxesRepository.save(blindBox);
        brandClient.update(id, request);
        return getById(id);
    }

    @Override
    public List<BlindBoxCategories> getAllCategory() {
        return blindBoxCategoriesRepository.findAll();
    }

}
