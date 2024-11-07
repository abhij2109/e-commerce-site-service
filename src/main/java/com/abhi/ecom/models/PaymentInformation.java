package com.abhi.ecom.models;

import jakarta.persistence.Entity;

import java.time.LocalDateTime;

public class PaymentInformation {

    private String cardHolderName;
    private String cardNumber;
    private String cvv;
    private LocalDateTime expiration;
}
