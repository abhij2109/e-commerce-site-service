package com.abhi.ecom.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Data
@RequiredArgsConstructor
@NoArgsConstructor
public class OrderItem {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    @JsonIgnore
    @ManyToOne
    private Order order;
    @ManyToOne
    private Product product;
    private String size;
    private Integer quantity;
    private Integer price;
    private Integer discountedPrice;
    private Long userId;
    private LocalDateTime deliveryDate;
}
