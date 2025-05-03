package com.security.validation

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

class SecurityValidatorTest {
    private val validator = SecurityValidator()

    @Test
    fun `test length validation`() {
        val result = validator.validateLength("test", 3, 5)
        assertTrue(result.isValid)
        assertEquals("Length is valid", result.message)

        val tooShort = validator.validateLength("te", 3, 5)
        assertFalse(tooShort.isValid)
        assertEquals("Input is too short. Minimum length: 3", tooShort.message)

        val tooLong = validator.validateLength("testing", 3, 5)
        assertFalse(tooLong.isValid)
        assertEquals("Input is too long. Maximum length: 5", tooLong.message)
    }

    @Test
    fun `test integer validation`() {
        val result = validator.validateInteger("123")
        assertTrue(result.isValid)
        assertEquals("Valid integer", result.message)

        val invalid = validator.validateInteger("abc")
        assertFalse(invalid.isValid)
        assertEquals("Input is not a valid integer", invalid.message)
    }

    @Test
    fun `test date validation`() {
        val result = validator.validateDate("2024-03-21")
        assertTrue(result.isValid)
        assertEquals("Valid date", result.message)

        val invalid = validator.validateDate("2024/03/21")
        assertFalse(invalid.isValid)
        assertEquals("Invalid date format. Expected format: yyyy-MM-dd", invalid.message)
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "test@example.com",
        "user.name@domain.co.uk",
        "user+tag@example.com"
    ])
    fun `test valid email formats`(email: String) {
        val result = validator.validateEmail(email)
        assertTrue(result.isValid)
        assertEquals("Valid email format", result.message)
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "invalid.email",
        "@example.com",
        "user@.com",
        "user@example."
    ])
    fun `test invalid email formats`(email: String) {
        val result = validator.validateEmail(email)
        assertFalse(result.isValid)
        assertEquals("Invalid email format", result.message)
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "+1234567890",
        "1234567890",
        "+441234567890"
    ])
    fun `test valid phone numbers`(phone: String) {
        val result = validator.validatePhoneNumber(phone)
        assertTrue(result.isValid)
        assertEquals("Valid phone number format", result.message)
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "123",
        "abc",
        "1234567890123456",
        "+1234567890123456"
    ])
    fun `test invalid phone numbers`(phone: String) {
        val result = validator.validatePhoneNumber(phone)
        assertFalse(result.isValid)
        assertEquals("Invalid phone number format", result.message)
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "valid_username",
        "user-name",
        "user123",
        "a_b-c"
    ])
    fun `test valid usernames`(username: String) {
        val result = validator.validateUsername(username)
        assertTrue(result.isValid)
        assertEquals("Valid username format", result.message)
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "ab",
        "username_with_more_than_twenty_characters",
        "user@name",
        "user name"
    ])
    fun `test invalid usernames`(username: String) {
        val result = validator.validateUsername(username)
        assertFalse(result.isValid)
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "' OR 1=1 --",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users; --",
        "' OR '1'='1"
    ])
    fun `test SQL injection detection`(input: String) {
        val result = validator.detectSQLInjection(input)
        assertFalse(result.isValid)
        assertEquals("Potential SQL injection detected", result.message)
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "& whoami",
        "; ls",
        "| cat /etc/passwd",
        "`rm -rf /`",
        "\${java.lang.Runtime.getRuntime().exec('whoami')}"
    ])
    fun `test command injection detection`(input: String) {
        val result = validator.detectCommandInjection(input)
        assertFalse(result.isValid)
        assertEquals("Potential command injection detected", result.message)
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "<script>alert(1)</script>",
        "javascript:alert(1)",
        "<img src=x onerror=alert(1)>",
        "onload=alert(1)"
    ])
    fun `test XSS detection`(input: String) {
        val result = validator.detectXSS(input)
        assertFalse(result.isValid)
        assertEquals("Potential XSS attack detected", result.message)
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "../../../etc/passwd",
        "..\\..\\..\\Windows\\System32",
        "%2e%2e%2fetc%2fpasswd",
        "%252e%252e%252fetc%252fpasswd"
    ])
    fun `test path traversal detection`(input: String) {
        val result = validator.detectPathTraversal(input)
        assertFalse(result.isValid)
        assertEquals("Potential path traversal attack detected", result.message)
    }

    @Test
    fun `test null byte detection`() {
        val result = validator.detectNullBytes("test\u0000.jpg")
        assertFalse(result.isValid)
        assertEquals("Null byte injection detected", result.message)
    }

    @Test
    fun `test base64 validation`() {
        val valid = validator.validateBase64("SGVsbG8gV29ybGQ=")
        assertTrue(valid.isValid)
        assertEquals("Valid Base64 encoding", valid.message)

        val invalid = validator.validateBase64("Not base64")
        assertFalse(invalid.isValid)
        assertEquals("Invalid Base64 encoding", invalid.message)
    }

    @Test
    fun `test comprehensive validation`() {
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

        // Valid email
        val valid = validator.validateInput("test@example.com", options)
        assertTrue(valid.isValid)
        assertEquals("All validations passed", valid.message)

        // Invalid email
        val invalid = validator.validateInput("invalid", options)
        assertFalse(invalid.isValid)
        assertEquals("Invalid email format", invalid.message)

        // Empty input
        val empty = validator.validateInput("", options)
        assertFalse(empty.isValid)
        assertEquals("Input cannot be empty", empty.message)

        // Too long
        val tooLong = validator.validateInput("very.long.email.address@example.com", options)
        assertFalse(tooLong.isValid)
        assertEquals("Input is too long. Maximum length: 20", tooLong.message)

        // Contains XSS
        val xss = validator.validateInput("<script>alert(1)</script>", options)
        assertFalse(xss.isValid)
        assertEquals("Potential XSS attack detected", xss.message)
    }
} 