package com.security.validation

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

class StringValidatorTest {
    private val validator = StringValidator()

    @Test
    fun `test valid input length`() {
        val result = validator.validate("valid input", maxLength = 20)
        assertTrue(result.isValid)
        assertEquals("Input is valid", result.message)
    }

    @Test
    fun `test input exceeds max length`() {
        val result = validator.validate("this input is too long", maxLength = 10)
        assertFalse(result.isValid)
        assertEquals("Input exceeds maximum length of 10 characters", result.message)
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "<script>alert('xss')</script>",
        "javascript:alert('xss')",
        "onerror=alert('xss')",
        "eval('alert(\"xss\")')",
        "expression(alert('xss'))"
    ])
    fun `test XSS attack detection`(input: String) {
        val result = validator.checkForXSS(input)
        assertFalse(result.isValid)
        assertEquals("Potential XSS attack detected", result.message)
    }

    @Test
    fun `test no XSS in safe input`() {
        val result = validator.checkForXSS("safe input")
        assertTrue(result.isValid)
        assertEquals("No XSS vulnerabilities detected", result.message)
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "http://localhost",
        "https://127.0.0.1",
        "http://169.254.169.254",
        "file:///etc/passwd",
        "gopher://internal",
        "dict://internal"
    ])
    fun `test SSRF attack detection`(input: String) {
        val result = validator.checkForSSRF(input)
        assertFalse(result.isValid)
        assertEquals("Potential SSRF attack detected", result.message)
    }

    @Test
    fun `test no SSRF in safe input`() {
        val result = validator.checkForSSRF("https://example.com")
        assertTrue(result.isValid)
        assertEquals("No SSRF vulnerabilities detected", result.message)
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "'; DROP TABLE users; --",
        "'; SELECT * FROM users; --",
        "'; UPDATE users SET password = 'hacked'; --",
        "'; INSERT INTO users (username, password) VALUES ('hacker', 'password'); --",
        "'; DELETE FROM users; --"
    ])
    fun `test SQL injection detection`(input: String) {
        val result = validator.checkForSQLInjection(input)
        assertFalse(result.isValid)
        assertEquals("Potential SQL injection attack detected", result.message)
    }

    @Test
    fun `test no SQL injection in safe input`() {
        val result = validator.checkForSQLInjection("SELECT * FROM users WHERE id = 1")
        assertTrue(result.isValid)
        assertEquals("No SQL injection vulnerabilities detected", result.message)
    }

    @Test
    fun `test HTML sanitization`() {
        val input = "<script>alert('xss')</script>"
        val sanitized = validator.sanitize(input)
        assertEquals("&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;", sanitized)
    }

    @Test
    fun `test combined validation and sanitization with safe input`() {
        val input = "safe input"
        val (result, sanitized) = validator.validateAndSanitize(input)
        assertTrue(result.isValid)
        assertEquals("Input is valid and secure", result.message)
        assertEquals(input, sanitized)
    }

    @Test
    fun `test combined validation and sanitization with XSS`() {
        val input = "<script>alert('xss')</script>"
        val (result, sanitized) = validator.validateAndSanitize(input)
        assertTrue(result.isValid)
        assertEquals("Input contained potential security issues and was sanitized", result.message)
        assertEquals("&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;", sanitized)
    }

    @Test
    fun `test combined validation and sanitization with SSRF`() {
        val input = "http://localhost"
        val (result, sanitized) = validator.validateAndSanitize(input)
        assertTrue(result.isValid)
        assertEquals("Input contained potential security issues and was sanitized", result.message)
        assertEquals("http://localhost", sanitized) // SSRF URLs are not sanitized, just detected
    }

    @Test
    fun `test combined validation and sanitization with SQL injection`() {
        val input = "'; DROP TABLE users; --"
        val (result, sanitized) = validator.validateAndSanitize(input)
        assertTrue(result.isValid)
        assertEquals("Input contained potential security issues and was sanitized", result.message)
        assertEquals("&#39;; DROP TABLE users; --", sanitized)
    }
} 