package com.microservice.jwt.controller;

import com.microservice.jwt.dto.AuthRequest;
import com.microservice.jwt.dto.RegisterRequest;
import com.microservice.jwt.entity.RoleEntity;
import com.microservice.jwt.entity.UserEntity;
import com.microservice.jwt.repository.RoleRepository;
import com.microservice.jwt.repository.UserRepository;
import com.microservice.jwt.security.JwtUtil;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@AllArgsConstructor
public class AuthController {

    private AuthenticationManager authManager;
    private JwtUtil jwtUtil;
    private UserRepository userRepository;
    private RoleRepository roleRepository;
    private PasswordEncoder encoder;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        System.out.println("Petición recibida: " + request);
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body("El usuario ya existe");
        }

        RoleEntity rol = roleRepository.findByName(request.getRol())
                .orElseThrow(() -> new UsernameNotFoundException("Rol no encontrado" +request.getRol()));

        UserEntity user = new UserEntity();
        user.setUsername(request.getUsername());
        user.setPassword(encoder.encode(request.getPassword()));
        user.setRole(rol);

        userRepository.save(user);
        return ResponseEntity.ok("Usuario registrado con exito");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {
        authManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(),request.getPassword()));

        UserDetails user = userRepository.findByUsername(request.getUsername())
                .map(u -> {
                    GrantedAuthority authority = new SimpleGrantedAuthority(u.getRole().getName());
                    return new User(u.getUsername(), u.getPassword(), List.of(authority));
                })
                .orElseThrow();

        String token = jwtUtil.generateToken(user);

        return ResponseEntity.ok(Map.of("token", token));
    }

}
