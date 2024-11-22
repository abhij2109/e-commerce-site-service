package com.abhi.ecom.controller.admincontrollers;

import com.abhi.ecom.constants.Constants;
import com.abhi.ecom.exceptions.ProductException;
import com.abhi.ecom.models.Product;
import com.abhi.ecom.request.CreateProductRequest;
import com.abhi.ecom.response.ApiResponse;
import com.abhi.ecom.service.ProductService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/admin/products")
public class AdminProductController {

    private final ProductService productService;

    @PostMapping("/")
    public ResponseEntity<Product> createProductHandler(@RequestBody CreateProductRequest request){
        Product product = productService.createProduct(request);
        return new ResponseEntity<>(product, HttpStatus.CREATED);
    }

    @DeleteMapping("/{productId}/delete")
    public ResponseEntity<ApiResponse> deleteProduct(@PathVariable Long productId)throws ProductException {

        String messageOfDeletion = productService.deleteProduct(productId);

        ApiResponse response = new ApiResponse();
        response.setMessage(messageOfDeletion);
        response.setStatus(Constants.TRUE);

        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @GetMapping("/all")
    public ResponseEntity<List<Product>> getAllProducts(){
        List<Product> productList = productService.findAllProducts();

        return new ResponseEntity<>(productList, HttpStatus.OK);
    }

    @PutMapping("/{productId}/update")
    public ResponseEntity<Product> updateProduct(@RequestBody Product product, @PathVariable Long productId)throws ProductException{
        Product updatedProduct = productService.updateProduct(productId, product);

        return new ResponseEntity<>(updatedProduct, HttpStatus.CREATED);
    }
}
