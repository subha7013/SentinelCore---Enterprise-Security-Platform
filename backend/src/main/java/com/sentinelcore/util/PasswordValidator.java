package com.sentinelcore.util;

import com.sentinelcore.exception.BadRequestException;
import org.springframework.util.StringUtils;

import java.util.regex.Pattern;

public class PasswordValidator {

    public static final String STRONG_PASSWORD_REGEX = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?]).{8,}$";
    public static final String PASSWORD_REQUIREMENT_MESSAGE = "Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.";

    private static final Pattern PATTERN = Pattern.compile(STRONG_PASSWORD_REGEX);

    public static boolean isValid(String password) {
        if (!StringUtils.hasText(password)) {
            return false;
        }
        return PATTERN.matcher(password).matches();
    }

    public static void validatePassword(String password) {
        if (!StringUtils.hasText(password)) {
            throw new BadRequestException("Password is required.");
        }
        if (password.length() < 8) {
            throw new BadRequestException("Password must be at least 8 characters long.");
        }
        if (!Pattern.compile(".*[A-Z].*").matcher(password).matches()) {
            throw new BadRequestException("Password must contain at least one uppercase letter.");
        }
        if (!Pattern.compile(".*[a-z].*").matcher(password).matches()) {
            throw new BadRequestException("Password must contain at least one lowercase letter.");
        }
        if (!Pattern.compile(".*\\d.*").matcher(password).matches()) {
            throw new BadRequestException("Password must contain at least one number.");
        }
        if (!Pattern.compile(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?].*").matcher(password).matches()) {
            throw new BadRequestException("Password must contain at least one special character.");
        }
    }
}
