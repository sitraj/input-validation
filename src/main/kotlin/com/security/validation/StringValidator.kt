package com.security.validation

import java.util.regex.Pattern
import org.owasp.encoder.Encode

class StringValidator {
    companion object {
        private val XSS_PATTERNS = listOf(
            Pattern.compile("<script.*?>.*?</script>", Pattern.CASE_INSENSITIVE),
            Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE),
            Pattern.compile("on\\w+\\s*=", Pattern.CASE_INSENSITIVE),
            Pattern.compile("eval\\s*\\(.*\\)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("expression\\s*\\(.*\\)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("vbscript:", Pattern.CASE_INSENSITIVE),
            Pattern.compile("data:", Pattern.CASE_INSENSITIVE),
            Pattern.compile("base64", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<!--.*-->", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<\\?.*\\?>", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<%.*%>", Pattern.CASE_INSENSITIVE),
            Pattern.compile("\\$\\{.*\\}", Pattern.CASE_INSENSITIVE)
        )

        private val SSRF_PATTERNS = listOf(
            Pattern.compile("^(http|https)://(localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0|\\[::1\\])"),
            Pattern.compile("^(http|https)://(169\\.254\\.|192\\.168\\.|10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)"),
            Pattern.compile("^(http|https)://(metadata\\.google\\.internal|169\\.254\\.169\\.254)"),
            Pattern.compile("file:///"),
            Pattern.compile("gopher://"),
            Pattern.compile("dict://"),
            Pattern.compile("^(http|https)://(localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0|\\[::1\\]):\\d+"),
            Pattern.compile("^(http|https)://(169\\.254\\.|192\\.168\\.|10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.):\\d+")
        )

        private val SQL_INJECTION_PATTERNS = listOf(
            Pattern.compile("'.*--"),
            Pattern.compile("'.*;"),
            Pattern.compile("'.*union.*select", Pattern.CASE_INSENSITIVE),
            Pattern.compile("'.*drop.*table", Pattern.CASE_INSENSITIVE),
            Pattern.compile("'.*delete.*from", Pattern.CASE_INSENSITIVE),
            Pattern.compile("'.*insert.*into", Pattern.CASE_INSENSITIVE),
            Pattern.compile("'.*update.*set", Pattern.CASE_INSENSITIVE),
            Pattern.compile("'.*exec\\s*\\(.*\\)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("'.*xp_cmdshell", Pattern.CASE_INSENSITIVE),
            Pattern.compile("'.*sp_", Pattern.CASE_INSENSITIVE),
            Pattern.compile("'.*sysobjects", Pattern.CASE_INSENSITIVE),
            Pattern.compile("'.*syscolumns", Pattern.CASE_INSENSITIVE)
        )
    }

    fun validate(input: String, maxLength: Int = 255): ValidationResult {
        if (input.isBlank()) {
            return ValidationResult(false, "Input cannot be blank")
        }
        if (input.length > maxLength) {
            return ValidationResult(false, "Input exceeds maximum length of $maxLength characters")
        }
        return ValidationResult(true, "Input is valid")
    }

    fun sanitize(input: String): String {
        // First, remove any null bytes
        val sanitized = input.replace("\u0000", "")
        // Then apply HTML encoding
        return Encode.forHtml(sanitized)
    }

    fun checkForXSS(input: String): ValidationResult {
        XSS_PATTERNS.forEach { pattern ->
            if (pattern.matcher(input).find()) {
                return ValidationResult(false, "Potential XSS attack detected")
            }
        }
        return ValidationResult(true, "No XSS vulnerabilities detected")
    }

    fun checkForSSRF(input: String): ValidationResult {
        SSRF_PATTERNS.forEach { pattern ->
            if (pattern.matcher(input).find()) {
                return ValidationResult(false, "Potential SSRF attack detected")
            }
        }
        return ValidationResult(true, "No SSRF vulnerabilities detected")
    }

    fun checkForSQLInjection(input: String): ValidationResult {
        SQL_INJECTION_PATTERNS.forEach { pattern ->
            if (pattern.matcher(input).find()) {
                return ValidationResult(false, "Potential SQL injection attack detected")
            }
        }
        return ValidationResult(true, "No SQL injection vulnerabilities detected")
    }

    fun validateAndSanitize(input: String, maxLength: Int = 255): Pair<ValidationResult, String> {
        val validationResult = validate(input, maxLength)
        if (!validationResult.isValid) {
            return Pair(validationResult, input)
        }

        val xssCheck = checkForXSS(input)
        val ssrfCheck = checkForSSRF(input)
        val sqlCheck = checkForSQLInjection(input)

        val needsSanitization = !xssCheck.isValid || !ssrfCheck.isValid || !sqlCheck.isValid
        val sanitized = if (needsSanitization) sanitize(input) else input

        return if (needsSanitization) {
            Pair(
                ValidationResult(true, "Input contained potential security issues and was sanitized"),
                sanitized
            )
        } else {
            Pair(ValidationResult(true, "Input is valid and secure"), input)
        }
    }
} 