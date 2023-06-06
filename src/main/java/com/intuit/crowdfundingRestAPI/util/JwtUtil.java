package com.intuit.crowdfundingRestAPI.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtUtil {

    private String SECRET_KEY = "secret";
    
    // Add a refresh token secret key
    private String REFRESH_SECRET_KEY = "refresh_secret";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername());
    }

    private String createToken(Map<String, Object> claims, String subject) {

        return Jwts.builder()
        		   .setClaims(claims)
        		   .setSubject(subject)
        		   .setIssuedAt(new Date(System.currentTimeMillis()))
        		   .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) //10hours Valid
        		   //.setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 )) // 1/2 mins
        		   .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
        		   .compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
    
 // Generate refresh token
    public String generateRefreshToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createRefreshToken(claims, userDetails.getUsername());
    }

    private String createRefreshToken(Map<String, Object> claims, String subject) {

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24 * 7)) //7 days Valid
                .signWith(SignatureAlgorithm.HS256, REFRESH_SECRET_KEY)
                .compact();
    }

    // Validate refresh token
    public Boolean validateRefreshToken(String token, UserDetails userDetails) {
        final String username = extractUsernameFromRefreshToken(token);
        return username.equals(userDetails.getUsername());
    }

    public String extractUsernameFromRefreshToken(String token) {
        return Jwts.parser().setSigningKey(REFRESH_SECRET_KEY).parseClaimsJws(token).getBody().getSubject();
    }
}