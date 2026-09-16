package com.sentinelcore.dto;

import com.sentinelcore.model.Role;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegisterRequest {
    @NotBlank(message = "Name is required")
    private String name;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Password is required")
    @jakarta.validation.constraints.Pattern(
            regexp = com.sentinelcore.util.PasswordValidator.STRONG_PASSWORD_REGEX,
            message = com.sentinelcore.util.PasswordValidator.PASSWORD_REQUIREMENT_MESSAGE
    )
    private String password;

    private Role role; // ANALYST or VIEWER for public registration

    private String department;
}
