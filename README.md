# Input Validation Library

A comprehensive Kotlin library for secure input validation, designed to prevent common security vulnerabilities including XSS, SQL injection, command injection, and path traversal attacks.

## Features

### Security Validations
- Cross-Site Scripting (XSS) detection
- SQL injection detection
- Command injection detection
- Path traversal detection
- Null byte injection detection

### Format Validations
- Email validation
- Phone number validation
- Username validation
- Alphanumeric validation

### Data Type Validations
- Integer validation
- Date validation (with custom format support)
- Base64 validation
- UTF-8 validation

### Other Validations
- Length validation
- Range validation
- Boundary testing
- Empty input checks

## Usage

### Basic Usage

```kotlin
val validator = SecurityValidator()

// Simple email validation
val emailResult = validator.validateEmail("user@example.com")
if (emailResult.isValid) {
    // Process valid email
}

// Simple length validation
val lengthResult = validator.validateLength("input", 3, 10)
if (lengthResult.isValid) {
    // Process valid length input
}
```

### Comprehensive Validation

```kotlin
val options = ValidationOptions(
    checkEmpty = true,
    checkLength = true,
    minLength = 3,
    maxLength = 20,
    checkType = false,
    checkFormat = true,
    expectedFormat = InputFormat.EMAIL,
    checkSecurity = true
)

val result = validator.validateInput("test@example.com", options)
if (result.isValid) {
    // Process valid input
} else {
    // Handle validation error: result.message
}
```

### Security Validation Examples

```kotlin
// XSS Detection
val xssResult = validator.detectXSS("<script>alert(1)</script>")

// SQL Injection Detection
val sqlResult = validator.detectSQLInjection("' OR '1'='1")

// Command Injection Detection
val cmdResult = validator.detectCommandInjection("; rm -rf /")

// Path Traversal Detection
val pathResult = validator.detectPathTraversal("../../../etc/passwd")
```

## Validation Order

The library follows a specific order for comprehensive validation:

1. Empty check (most basic)
2. Security checks (most critical)
   - XSS detection
   - SQL injection detection
   - Command injection detection
   - Path traversal detection
   - Null byte detection
3. Length validation
4. Format validation
5. Type validation

## Installation

Add the following dependency to your project:

```kotlin
// build.gradle.kts
dependencies {
    implementation("com.security:input-validation:1.0.0")
}
```

## Testing

The library includes comprehensive test coverage. Run tests using:

```bash
./gradlew test
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security

If you discover any security-related issues, please email itrajsr@gmail.com instead of using the issue tracker.

## Credits

Developed by Shounak Itraj 