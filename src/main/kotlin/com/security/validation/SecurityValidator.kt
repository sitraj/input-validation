package com.security.validation

import java.util.regex.Pattern
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException
import java.util.Base64
import java.nio.charset.StandardCharsets

class SecurityValidator {
    companion object {
        // Common patterns
        private val EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")
        private val PHONE_PATTERN = Pattern.compile("^\\+?[0-9]{10,15}$")
        private val USERNAME_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{3,20}$")
        private val ALPHANUMERIC_PATTERN = Pattern.compile("^[a-zA-Z0-9]+$")
        
        // Common injection patterns
        private val SQL_INJECTION_PATTERNS = listOf(
            Pattern.compile(".*'.*--.*"),
            Pattern.compile(".*'.*;.*"),
            Pattern.compile(".*'.*union.*select.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*'.*drop.*table.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*'.*delete.*from.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*'.*insert.*into.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*'.*update.*set.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*'.*exec\\s*\\(.*\\).*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*'.*xp_cmdshell.*", Pattern.CASE_INSENSITIVE),
            Pattern.compile(".*'.*OR.*'.*'.*'.*", Pattern.CASE_INSENSITIVE)
        )

        private val COMMAND_INJECTION_PATTERNS = listOf(
            Pattern.compile(".*&.*"),
            Pattern.compile(".*;.*"),
            Pattern.compile(".*\\|.*"),
            Pattern.compile(".*`.*`.*"),
            Pattern.compile(".*\\$\\{.*\\}.*"),
            Pattern.compile(".*\\$\\(.*\\).*")
        )

        private val XSS_PATTERNS = listOf(
            Pattern.compile("<script.*?>.*?</script>", Pattern.CASE_INSENSITIVE),
            Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE),
            Pattern.compile("on\\w+\\s*=", Pattern.CASE_INSENSITIVE),
            Pattern.compile("eval\\s*\\(.*\\)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("expression\\s*\\(.*\\)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<img.*?src=.*?onerror=.*?>", Pattern.CASE_INSENSITIVE)
        )

        private val PATH_TRAVERSAL_PATTERNS = listOf(
            Pattern.compile(".*\\.\\./.*"),
            Pattern.compile(".*\\.\\\\.*"),
            Pattern.compile(".*%2e%2e.*"),
            Pattern.compile(".*%252e%252e.*")
        )
    }

    // Length validation
    fun validateLength(input: String, min: Int, max: Int): ValidationResult {
        return when {
            input.length < min -> ValidationResult(false, "Input is too short. Minimum length: $min")
            input.length > max -> ValidationResult(false, "Input is too long. Maximum length: $max")
            else -> ValidationResult(true, "Length is valid")
        }
    }

    // Data type validation
    fun validateInteger(input: String): ValidationResult {
        return try {
            input.toInt()
            ValidationResult(true, "Valid integer")
        } catch (e: NumberFormatException) {
            ValidationResult(false, "Input is not a valid integer")
        }
    }

    fun validateDate(input: String, format: String = "yyyy-MM-dd"): ValidationResult {
        return try {
            val formatter = DateTimeFormatter.ofPattern(format)
            LocalDate.parse(input, formatter)
            ValidationResult(true, "Valid date")
        } catch (e: DateTimeParseException) {
            ValidationResult(false, "Invalid date format. Expected format: $format")
        }
    }

    // Format validation
    fun validateEmail(input: String): ValidationResult {
        return if (EMAIL_PATTERN.matcher(input).matches()) {
            ValidationResult(true, "Valid email format")
        } else {
            ValidationResult(false, "Invalid email format")
        }
    }

    fun validatePhoneNumber(input: String): ValidationResult {
        return if (PHONE_PATTERN.matcher(input).matches()) {
            ValidationResult(true, "Valid phone number format")
        } else {
            ValidationResult(false, "Invalid phone number format")
        }
    }

    // Whitelist validation
    fun validateUsername(input: String): ValidationResult {
        return if (USERNAME_PATTERN.matcher(input).matches()) {
            ValidationResult(true, "Valid username format")
        } else {
            ValidationResult(false, "Invalid username format. Only alphanumeric characters, underscores, and hyphens are allowed")
        }
    }

    fun validateAlphanumeric(input: String): ValidationResult {
        return if (ALPHANUMERIC_PATTERN.matcher(input).matches()) {
            ValidationResult(true, "Valid alphanumeric input")
        } else {
            ValidationResult(false, "Input contains non-alphanumeric characters")
        }
    }

    // Range validation
    fun validateRange(input: Int, min: Int, max: Int): ValidationResult {
        return when {
            input < min -> ValidationResult(false, "Value is below minimum: $min")
            input > max -> ValidationResult(false, "Value is above maximum: $max")
            else -> ValidationResult(true, "Value is within valid range")
        }
    }

    // Injection attack detection
    fun detectSQLInjection(input: String): ValidationResult {
        SQL_INJECTION_PATTERNS.forEach { pattern ->
            if (pattern.matcher(input).find()) {
                return ValidationResult(false, "Potential SQL injection detected")
            }
        }
        return ValidationResult(true, "No SQL injection detected")
    }

    fun detectCommandInjection(input: String): ValidationResult {
        COMMAND_INJECTION_PATTERNS.forEach { pattern ->
            if (pattern.matcher(input).find()) {
                return ValidationResult(false, "Potential command injection detected")
            }
        }
        return ValidationResult(true, "No command injection detected")
    }

    fun detectXSS(input: String): ValidationResult {
        XSS_PATTERNS.forEach { pattern ->
            if (pattern.matcher(input).find()) {
                return ValidationResult(false, "Potential XSS attack detected")
            }
        }
        return ValidationResult(true, "No XSS vulnerabilities detected")
    }

    fun detectPathTraversal(input: String): ValidationResult {
        PATH_TRAVERSAL_PATTERNS.forEach { pattern ->
            if (pattern.matcher(input).find()) {
                return ValidationResult(false, "Potential path traversal attack detected")
            }
        }
        return ValidationResult(true, "No path traversal detected")
    }

    // Null byte detection
    fun detectNullBytes(input: String): ValidationResult {
        if (input.contains("\u0000")) {
            return ValidationResult(false, "Null byte injection detected")
        }
        return ValidationResult(true, "No null bytes detected")
    }

    // Encoding/decoding validation
    fun validateBase64(input: String): ValidationResult {
        return try {
            Base64.getDecoder().decode(input)
            ValidationResult(true, "Valid Base64 encoding")
        } catch (e: IllegalArgumentException) {
            ValidationResult(false, "Invalid Base64 encoding")
        }
    }

    fun validateUTF8(input: String): ValidationResult {
        return try {
            input.toByteArray(StandardCharsets.UTF_8)
            ValidationResult(true, "Valid UTF-8 encoding")
        } catch (e: Exception) {
            ValidationResult(false, "Invalid UTF-8 encoding")
        }
    }

    // Boundary testing
    fun validateBoundaries(input: String, min: Int, max: Int): ValidationResult {
        return when {
            input.isEmpty() -> ValidationResult(false, "Input cannot be empty")
            input.length < min -> ValidationResult(false, "Input is below minimum length: $min")
            input.length > max -> ValidationResult(false, "Input exceeds maximum length: $max")
            else -> ValidationResult(true, "Input is within valid boundaries")
        }
    }

    // Comprehensive validation
    fun validateInput(input: String, options: ValidationOptions = ValidationOptions()): ValidationResult {
        // Check for empty input first
        if (options.checkEmpty && input.isEmpty()) {
            return ValidationResult(false, "Input cannot be empty")
        }

        // Security checks first (most critical)
        if (options.checkSecurity) {
            // XSS (check first as it's most common)
            val xssResult = detectXSS(input)
            if (!xssResult.isValid) return xssResult

            // SQL Injection
            val sqlResult = detectSQLInjection(input)
            if (!sqlResult.isValid) return sqlResult

            // Command Injection
            val cmdResult = detectCommandInjection(input)
            if (!cmdResult.isValid) return cmdResult

            // Path Traversal
            val pathResult = detectPathTraversal(input)
            if (!pathResult.isValid) return pathResult

            // Null Bytes
            val nullResult = detectNullBytes(input)
            if (!nullResult.isValid) return nullResult
        }

        // Length validation
        if (options.checkLength) {
            val lengthResult = validateLength(input, options.minLength, options.maxLength)
            if (!lengthResult.isValid) {
                return lengthResult
            }
        }

        // Format validation
        if (options.checkFormat) {
            val formatResult = when (options.expectedFormat) {
                InputFormat.EMAIL -> validateEmail(input)
                InputFormat.PHONE -> validatePhoneNumber(input)
                InputFormat.USERNAME -> validateUsername(input)
                else -> ValidationResult(true, "Format validation skipped")
            }
            if (!formatResult.isValid) {
                return formatResult
            }
        }

        // Type validation (last as it's least critical)
        if (options.checkType) {
            val typeResult = when (options.expectedType) {
                InputType.INTEGER -> validateInteger(input)
                InputType.DATE -> validateDate(input, options.dateFormat)
                else -> ValidationResult(true, "Type validation skipped")
            }
            if (!typeResult.isValid) {
                return typeResult
            }
        }

        return ValidationResult(true, "All validations passed")
    }
}

data class ValidationOptions(
    val checkEmpty: Boolean = true,
    val checkLength: Boolean = true,
    val minLength: Int = 1,
    val maxLength: Int = 255,
    val checkType: Boolean = false,
    val expectedType: InputType = InputType.STRING,
    val checkFormat: Boolean = false,
    val expectedFormat: InputFormat = InputFormat.NONE,
    val checkSecurity: Boolean = true,
    val dateFormat: String = "yyyy-MM-dd"
)

enum class InputType {
    STRING, INTEGER, DATE
}

enum class InputFormat {
    NONE, EMAIL, PHONE, USERNAME
} 