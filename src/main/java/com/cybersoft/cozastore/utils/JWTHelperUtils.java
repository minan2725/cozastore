package com.cybersoft.cozastore.utils;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

@Component
public class JWTHelperUtils {

    // @Value : Giup lay key khai bao tren file application.properties
    @Value("${jwt.token.key}")
    String secretKey;
    /**
     * B1: Tao key
     * B2: Su dung key moi tao de sinh ra token
     *
     */
    public String generateToken(String data){

//        SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);
//        String key = Encoders.BASE64.encode(secretKey.getEncoded());
//        System.out.println(key);

        // Lay secret key da tao trc do de su dung
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
        // Dung key de tao ra token
        String token = Jwts.builder().setSubject(data).signWith(key).compact();
        return token;
    }

    public String validToken(String token){
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secretKey));
        // chuan bi chia khoa de tien hanh giai ma
        return Jwts.parserBuilder().setSigningKey(key).build()
                .parseClaimsJws(token) //truyen token can giai ma
                .getBody().getSubject();

    }
}
