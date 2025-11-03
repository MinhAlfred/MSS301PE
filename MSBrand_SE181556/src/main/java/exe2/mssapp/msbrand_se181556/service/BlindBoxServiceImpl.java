package exe2.mssapp.msbrand_se181556.service;


import exe2.mssapp.msbrand_se181556.dto.BlindBoxRequest;
import exe2.mssapp.msbrand_se181556.model.BlindBoxes;
import exe2.mssapp.msbrand_se181556.model.Brand;
import exe2.mssapp.msbrand_se181556.repository.BlindBoxesRepository;
import exe2.mssapp.msbrand_se181556.repository.BrandRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.List;

@Service
@RequiredArgsConstructor
public class BlindBoxServiceImpl implements BlindBoxService {
    private final BlindBoxesRepository blindBoxesRepository;
    private final BrandRepository brandRepository;

    @Override
    public void create(BlindBoxRequest request) {
        LocalDate inputDate = request.getReleaseDate();
        LocalDate today = LocalDate.now();
        if (!inputDate.equals(today)) {
            throw new RuntimeException("Release date must be today");
        }
        Brand brand = brandRepository.findById(request.getBrandId()).orElseThrow(
                () -> new RuntimeException("Brand not found")
        );

        BlindBoxes blindBox = BlindBoxes.builder()
                .name(request.getName())
                .categoryId(request.getCategoryId())
                .brand(brand)
                .price(request.getPrice())
                .realeaseDate(request.getReleaseDate())
                .stock(request.getStock())
                .build();
        BlindBoxes savedBlindBox = blindBoxesRepository.save(blindBox);
    }

    @Override
    public void deleteById(Integer id) {
        BlindBoxes blindBox = blindBoxesRepository.findById(id).orElseThrow(
                () -> new RuntimeException("Blind box not found")
        );
        blindBoxesRepository.delete(blindBox);
    }

    @Override
    public void update(Integer id, BlindBoxRequest request) {
        BlindBoxes blindBox = blindBoxesRepository.findById(id).orElseThrow(
                () -> new RuntimeException("Blind box not found")
        );
        Brand brand = brandRepository.findById(request.getBrandId()).orElseThrow(
                () -> new RuntimeException("Brand not found")
        );
        blindBox.setName(request.getName());
        blindBox.setCategoryId(request.getCategoryId());
        blindBox.setBrand(brand);
        blindBox.setPrice(request.getPrice());
        blindBox.setRealeaseDate(request.getReleaseDate());
        blindBox.setStock(request.getStock());
        blindBoxesRepository.save(blindBox);
    }
    @Override
    public String getBlindBoxNameById(Integer id) {
        BlindBoxes blindBox = blindBoxesRepository.findById(id).orElseThrow(
                () -> new RuntimeException("Blind box not found")
        );
        return blindBox.getBrand().getBrandName();
    }

    @Override
    public List<Brand> getAll() {
        return brandRepository.findAll();
    }

}
