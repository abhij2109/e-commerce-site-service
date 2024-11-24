package com.abhi.ecom.service.implementations;

import com.abhi.ecom.constants.Constants;
import com.abhi.ecom.exceptions.ProductException;
import com.abhi.ecom.models.Category;
import com.abhi.ecom.models.Product;
import com.abhi.ecom.repository.CategoryRepository;
import com.abhi.ecom.repository.ProductRepository;
import com.abhi.ecom.request.CreateProductRequest;
import com.abhi.ecom.service.ProductService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class ProductServiceImplementation implements ProductService {

    private final ProductRepository productRepository;
    private final CategoryRepository categoryRepository;

    @Override
    public Product createProduct(CreateProductRequest request) {

        Category topLevel= categoryRepository.findByName(request.getTopLevelCategory());
        if(topLevel == null){
            Category topLevelCategory = new Category();
            topLevelCategory.setName(request.getTopLevelCategory());
            topLevelCategory.setLevel(1);

            topLevel = categoryRepository.save(topLevelCategory);
        }

        Category secondLevel= categoryRepository.findByNameAndParent(request.getSecondLevelCategory(), topLevel.getName());
        if(secondLevel == null){
            Category secondLevelCategory = new Category();
            secondLevelCategory.setName(request.getSecondLevelCategory());
            secondLevelCategory.setParentCategory(topLevel);
            secondLevelCategory.setLevel(2);

            secondLevel = categoryRepository.save(secondLevelCategory);
        }

        Category thirdLevel= categoryRepository.findByNameAndParent(request.getThirdLevelCategory(), secondLevel.getName());
        if(thirdLevel == null){
            Category thirdLevelCategory = new Category();
            thirdLevelCategory.setName(request.getThirdLevelCategory());
            thirdLevelCategory.setParentCategory(secondLevel);
            thirdLevelCategory.setLevel(3);

            thirdLevel = categoryRepository.save(thirdLevelCategory);
        }

        Product product = new Product();
        product.setTitle(request.getTitle());
        product.setColour(request.getColour());
        product.setDescription(request.getDescription());
        product.setDiscounted_price(request.getDiscountedPrice());
        product.setDiscount_percent(request.getDiscountPercent());
        product.setImageUrl(request.getImageUrl());
        product.setBrand(request.getBrand());
        product.setPrice(request.getPrice());
        product.setSizes(request.getSizes());
        product.setQuantity(request.getQuantity());
        product.setCategory(thirdLevel);
        product.setCreatedAt(LocalDateTime.now());

        return productRepository.save(product);

    }

    @Override
    public String deleteProduct(Long productId) throws ProductException {
        Product product = findProductById(productId);
        product.getSizes().clear();
        productRepository.delete(product);

        return Constants.PRODUCT_DELETED_SUCCESS;
    }

    @Override
    public Product updateProduct(Long productId, Product productToUpdate) throws ProductException {
        Product product = findProductById(productId);
        if(productToUpdate.getQuantity()!=0){
            product.setQuantity(productToUpdate.getQuantity());
        }
        return productRepository.save(product);
    }

    @Override
    public Product findProductById(Long productId) throws ProductException {
        if(productRepository.findById(productId).isPresent()){
            return productRepository.findById(productId).get();
        }
        throw new ProductException(Constants.PRODUCT_NOT_FOUND + productId);
    }

    @Override
    public List<Product> findProductByCategory(String category) {
        return null;
    }

    @Override
    public Page<Product> getAllProduct(String category, List<String> colors, List<String> sizes,
                                       Integer minPrice, Integer maxPrice, Integer minDiscount,
                                       String sort, String stock, Integer pageNumber, Integer pageSize) {

        Pageable page = PageRequest.of(pageNumber, pageSize);
        List<Product> products = productRepository.filterProducts(category, minPrice, maxPrice, minDiscount, sort);

        if(!colors.isEmpty()) {
            products = products.stream().filter(product -> colors.stream().anyMatch(colour -> colour.equalsIgnoreCase(product.getColour()))).toList();
        }
        if(stock!=null){
            if(stock.equals(Constants.IN_STOCK)){
                products = products.stream().filter(product->product.getQuantity()>0).collect(Collectors.toList());
            }else if(stock.equals(Constants.OUT_OF_STOCK)){
                products = products.stream().filter(product -> product.getQuantity()<1).collect(Collectors.toList());
            }
        }

        int startIndex = (int) page.getOffset();
        int endIndex = Math.min(startIndex + page.getPageSize(), products.size());

        List<Product> pageContent = products.subList(startIndex, endIndex);

        Page<Product> filteredProducts = new PageImpl<>(pageContent, page, products.size());
        return filteredProducts;
    }

    @Override
    public List<Product> findAllProducts() {
        return null;
    }
}
