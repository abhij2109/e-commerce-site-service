package com.abhi.ecom.request;

import com.abhi.ecom.models.Size;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Embedded;
import lombok.Builder;
import lombok.Data;

import java.util.HashSet;
import java.util.Set;

@Data
@Builder
public class CreateProductRequest {

    private String title;
    private String description;
    private Integer price;
    private Integer discountedPrice;
    private Integer discountPercent;
    private Integer quantity;
    private String brand;
    private String colour;
    private Set<Size> sizes = new HashSet<>();
    private String imageUrl;
    private String topLevelCategory;
    private String secondLevelCategory;
    private String thirdLevelCategory;
}
