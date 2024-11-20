package com.abhi.ecom.request;

import lombok.Data;

@Data
public class RatingRequest {
    private Long productId;
    private double rating;
}
