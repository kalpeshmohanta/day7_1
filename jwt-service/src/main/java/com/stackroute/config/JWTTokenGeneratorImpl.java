package com.stackroute.config;

import java.util.HashMap;
import java.util.Map;
import java.util.Date;

import com.stackroute.domain.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/*
 * This class is implementing the JWTTokenGenerator interface. This class has to be annotated with
 * @Service annotation.
 * @Service indicates annotated class is a service
 * which hold business logic in the Service layer
 *
 * */
@Service
public class JWTTokenGeneratorImpl implements JWTTokenGenerator {

    /**
     * To get the property values
     */
    @Value("${jwt.secret}")
    private String secret;

    @Value("${app.jwttoken.message}")
    private String message;

    @Override
    public Map<String, String> generateToken(User user) {
   //     String jwtToken = "";
        /*
         * Generate JWT token and store in String jwtToken
         */
        Map<String, String> jwtTokenMap = new HashMap<>();
        String token = Jwts.builder().setSubject(user.getId()).
        		setIssuedAt(new Date(System.currentTimeMillis())).
        		setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 *60)).
        		signWith(SignatureAlgorithm.HS256, secret).compact();
        	jwtTokenMap.put("token", token);
        	jwtTokenMap.put("message", message);
        
        		

        return jwtTokenMap;
    }
}
