# Input Validation Library

A comprehensive Kotlin library for input validation and sanitization to prevent security vulnerabilities.

## Features

- **String Validation**
  - Length validation
  - XSS prevention
  - SQL injection prevention
  - SSRF prevention
  - HTML escaping
  - Pattern matching

- **Number Validation**
  - Range validation
  - Type checking
  - Format validation

- **URL Validation**
  - Protocol validation
  - Domain validation
  - Path validation
  - Query parameter validation
  - SSRF prevention

- **File Validation**
  - File extension validation
  - MIME type validation
  - Size validation
  - Content validation

- **Advanced Validation**
  - Date format validation
  - IP address validation (IPv4 and IPv6)
  - UUID validation (v4 and v6)
  - Custom format validation

## Installation

Add the following dependency to your `build.gradle.kts`:

```kotlin
dependencies {
    implementation("com.security:validation:1.0.0")
}
```

## Usage

### String Validation

```kotlin
val validator = StringValidator()

// Basic validation
val result = validator.validate("input string", maxLength = 100)

// Security checks
val xssCheck = validator.checkForXSS("<script>alert('xss')</script>")
val ssrfCheck = validator.checkForSSRF("http://localhost")
val sqlCheck = validator.checkForSQLInjection("'; DROP TABLE users; --")

// Sanitization
val sanitized = validator.sanitize("<script>alert('xss')</script>")

// Combined validation and sanitization
val (validationResult, sanitizedInput) = validator.validateAndSanitize("input string")
```

### Advanced Validation

```kotlin
val advancedValidator = AdvancedValidator()

// Date validation
val dateResult = advancedValidator.validateDate("2024-05-03", "yyyy-MM-dd")

// IP address validation
val ipv4Result = advancedValidator.validateIPAddress("192.168.1.1")
val ipv6Result = advancedValidator.validateIPAddress("2001:0db8:85a3:0000:0000:8a2e:0370:7334")

// UUID validation
val uuidv4Result = advancedValidator.validateUUID("123e4567-e89b-12d3-a456-426614174000", version = 4)
val uuidv6Result = advancedValidator.validateUUID("1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed", version = 6)

// String validation with security checks
val (validationResult, sanitizedInput) = validator.validateAndSanitize("input string")
```

## Security Features

### XSS Prevention
- Detects and sanitizes script tags
- Prevents JavaScript event handlers
- Escapes HTML special characters
- Validates input patterns

### SQL Injection Prevention
- Detects common SQL injection patterns
- Escapes special characters
- Validates input patterns
- Sanitizes SQL keywords

### SSRF Prevention
- Validates URLs against known internal IP ranges
- Blocks access to localhost and internal services
- Prevents access to metadata services
- Validates URL protocols

### Additional Security Measures
- Input length validation
- Pattern matching
- Type checking
- Format validation
- Content sanitization

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 