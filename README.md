# Input Validation Library

A comprehensive Kotlin library for secure input validation, designed to prevent common security vulnerabilities including XSS, SQL injection, and SSRF attacks.

## Features

- String validation and sanitization
- File validation with MIME type checking
- URL validation with SSRF protection
- Advanced validation for:
  - Dates
  - IP addresses
  - UUIDs
- Protection against:
  - XSS (Cross-Site Scripting)
  - SQL Injection
  - SSRF (Server-Side Request Forgery)
  - Path Traversal
  - File Upload Vulnerabilities

## Installation

### Gradle

Add the following to your `build.gradle.kts`:

```kotlin
repositories {
    mavenCentral()
    maven {
        url = uri("https://github.com/sitraj/input-validation/packages")
    }
}

dependencies {
    implementation("com.security:input-validation:1.0.0")
}
```

### Maven

Add the following to your `pom.xml`:

```xml
<dependency>
    <groupId>com.security</groupId>
    <artifactId>input-validation</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Usage

### String Validation

```kotlin
val validator = StringValidator()

// Basic validation
val result = validator.validate("input", maxLength = 255)
if (result.isValid) {
    // Process input
}

// XSS protection
val xssResult = validator.checkForXSS("<script>alert('xss')</script>")
if (!xssResult.isValid) {
    // Handle XSS attempt
}

// Combined validation and sanitization
val (validationResult, sanitizedInput) = validator.validateAndSanitize(userInput)
if (validationResult.isValid) {
    // Use sanitizedInput safely
}
```

### File Validation

```kotlin
val fileValidator = FileValidator()

// Validate file
val fileResult = fileValidator.validateFile(file)
if (!fileResult.isValid) {
    // Handle invalid file
}

// Check file type
val mimeResult = fileValidator.validateMimeType(file)
if (!mimeResult.isValid) {
    // Handle invalid file type
}

// Validate file size
val sizeResult = fileValidator.validateFileSize(file, maxSize = 5 * 1024 * 1024) // 5MB
if (!sizeResult.isValid) {
    // Handle oversized file
}
```

### URL Validation

```kotlin
val urlValidator = UrlValidator()

// Validate URL
val urlResult = urlValidator.validateUrl("https://example.com")
if (!urlResult.isValid) {
    // Handle invalid URL
}

// Validate and sanitize URL
val (validationResult, sanitizedUrl) = urlValidator.validateAndSanitize(userInputUrl)
if (validationResult.isValid) {
    // Use sanitizedUrl safely
}
```

### Advanced Validation

```kotlin
val advancedValidator = AdvancedValidator()

// Validate date
val dateResult = advancedValidator.validateDate("2024-03-21")

// Validate IP address
val ipResult = advancedValidator.validateIPAddress("192.168.1.1")

// Validate UUID
val uuidResult = advancedValidator.validateUUID("550e8400-e29b-41d4-a716-446655440000")
```

## Security Features

- Comprehensive XSS pattern detection
- SQL injection prevention
- SSRF protection with internal network access prevention
- Null byte injection protection
- Path traversal prevention
- File type validation
- ZIP file bomb protection
- Executable file detection
- Maximum length restrictions
- Input sanitization

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Version History

- 1.0.0 (2024-03-21): Initial release
  - Core validation functionality
  - Security features
  - Comprehensive test coverage 