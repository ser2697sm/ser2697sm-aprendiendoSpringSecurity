package com.microservice.jwt.security;

import javax.crypto.SecretKey;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class JwtUtil {
    // 🔑 Clave secreta de firma
    private final SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    //Genera un token con username y roles
    public String generateToken(UserDetails userDetails) {
        Map<String,Object> claims = new HashMap<>();
        claims.put("roles",userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());

        Instant now = Instant.now();

        return Jwts.builder()
                .claims(claims)                       // Claims personalizados (roles)
                .subject(userDetails.getUsername())   // Nombre de usuario
                .issuedAt(Date.from(now))             // Fecha de emisión
                .expiration(Date.from(now.plus(1, ChronoUnit.HOURS))) // Expiración
                .signWith(key)                        // Firma del token con clave secreta
                .compact();
    }

    //Extrae usermane del token
    public String extractUsername(String token) {
        return parseToken(token).getBody().getSubject();
    }

    //Extrae roles del token
    public List<String> extractRoles(String token) {
        var roles = parseToken(token).getBody().get("roles");

        if(roles instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }
        return List.of();
    }

    //Valida si el token pertenece al usuario
    public boolean validateToken(String token,UserDetails userDetails) {
        try {
            String username = extractUsername(token);
            return username.equals(userDetails.getUsername());
        }catch (JwtException e) {
            return false;
        }
    }

    //Paser con configuracion jackson y clave secreta
    private Jws<Claims> parseToken(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token);
    }

    public SecretKey getKey() {
        return key;
    }

}
