package com.abhi.ecom.config;

import com.abhi.ecom.constants.Constants;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
public class JwtProvider {

    SecretKey key = Keys.hmacShaKeyFor(Constants.SECRET_KEY.getBytes());
    public String generateToken(Authentication authentication){
        String jwt = Jwts.builder()
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime()+846000000))
                .claim("email", authentication.getName())
                .signWith(key)
                .compact();
        return jwt;
    }

    public String getEmailFromToken(String jwt){
        jwt = jwt.substring(7);
        Claims claims = Jwts.parser().verifyWith(key).build().parseSignedClaims(jwt).getPayload();
        String email = String.valueOf(claims.get("email"));
        return email;
    }
}
