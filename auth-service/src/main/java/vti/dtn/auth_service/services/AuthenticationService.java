package vti.dtn.auth_service.services;

import lombok.RequiredArgsConstructor;
import org.apache.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import vti.dtn.auth_service.dto.reponse.LoginResponse;
import vti.dtn.auth_service.dto.reponse.RegisterResponse;
import vti.dtn.auth_service.dto.request.LoginRequest;
import vti.dtn.auth_service.dto.request.RegisterRequest;
import vti.dtn.auth_service.entity.UserEntity;
import vti.dtn.auth_service.entity.enums.Role;
import vti.dtn.auth_service.repo.UserRepository;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public RegisterResponse register(RegisterRequest registerRequest){
        String email = registerRequest.getEmail();
        String userName = registerRequest.getUsername();
        String password = registerRequest.getPassword();
        String role = registerRequest.getRole();
        String firstName = registerRequest.getFirstName();
        String lastName = registerRequest.getLastName();

        Optional<UserEntity> userEntityByEmail = userRepository.findByEmail(email);
        Optional<UserEntity> userEntityByUsername = userRepository.findByUsername(userName);

        if (userEntityByEmail.isPresent() || userEntityByUsername.isPresent()) {
            return RegisterResponse.builder()
                    .status(400)
                    .message("User already exists!")
                    .build();
        }

        UserEntity userEntity = UserEntity.builder()
                .username(userName)
                .firstName(firstName)
                .lastName(lastName)
                .email(email)
                .password(passwordEncoder.encode(password)) // ⚠️ Should be encoded!
                .role(Role.toEnum(role)) // Convert string role to enum
                .build();

        userRepository.save(userEntity);

        return RegisterResponse.builder()
                .status(HttpStatus.SC_OK)
                .message("User created successfully")
                .build();

    }

    public LoginResponse login(LoginRequest loginRequest){
        String username = loginRequest.getUsername();
        String password = loginRequest.getPassword();

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        authenticationManager.authenticate(usernamePasswordAuthenticationToken);

        Optional<UserEntity> userEntityByUsername = userRepository.findByUsername(username);
        if(userEntityByUsername.isPresent()){
            UserEntity userEntity = userEntityByUsername.get();
            String accessToken = jwtService.generateAccessToken(userEntity);
            String refreshToken = jwtService.generateRefreshToken(userEntity);

            userEntity.setAccessToken(accessToken);
            userEntity.setRefreshToken(refreshToken);
            userRepository.save(userEntity);

            return LoginResponse.builder()
                    .status(HttpStatus.SC_OK)
                    .message("Login successful")
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .userId(userEntity.getId())
                    .build();
        }else {
            return LoginResponse.builder()
                    .status(HttpStatus.SC_UNAUTHORIZED)
                    .message("Invalid username or password")
                    .build();
        }
    }
}
