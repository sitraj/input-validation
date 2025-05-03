package com.security.validation

import java.net.URL
import java.net.MalformedURLException

class UrlValidator {
    companion object {
        private val ALLOWED_PROTOCOLS = setOf("http", "https")
        private val BLOCKED_DOMAINS = setOf(
            "localhost", "127.0.0.1", "0.0.0.0", "[::1]",
            "169.254.169.254", // AWS metadata endpoint
            "metadata.google.internal" // GCP metadata endpoint
        )
        private val INTERNAL_IP_PATTERNS = listOf(
            "^10\\.",
            "^172\\.(1[6-9]|2[0-9]|3[0-1])\\.",
            "^192\\.168\\.",
            "^169\\.254\\."
        ).map { Regex(it) }
    }

    fun validateUrl(urlString: String): ValidationResult {
        return try {
            val url = URL(urlString)
            validateProtocol(url)
                .takeIf { it.isValid }
                ?.let { validateDomain(url) }
                ?.takeIf { it.isValid }
                ?.let { validatePath(url) }
                ?: ValidationResult(false, "Invalid URL")
        } catch (e: MalformedURLException) {
            ValidationResult(false, "Malformed URL: ${e.message}")
        }
    }

    private fun validateProtocol(url: URL): ValidationResult {
        if (!ALLOWED_PROTOCOLS.contains(url.protocol)) {
            return ValidationResult(false, "Protocol '${url.protocol}' is not allowed. Allowed protocols: ${ALLOWED_PROTOCOLS.joinToString(", ")}")
        }
        return ValidationResult(true, "Protocol is valid")
    }

    private fun validateDomain(url: URL): ValidationResult {
        val host = url.host.lowercase()
        
        // Check blocked domains
        if (BLOCKED_DOMAINS.contains(host)) {
            return ValidationResult(false, "Domain '$host' is blocked")
        }

        // Check internal IP patterns
        if (INTERNAL_IP_PATTERNS.any { it.matches(host) }) {
            return ValidationResult(false, "Internal IP addresses are not allowed")
        }

        return ValidationResult(true, "Domain is valid")
    }

    private fun validatePath(url: URL): ValidationResult {
        val path = url.path
        
        // Check for directory traversal
        if (path.contains("../") || path.contains("..\\")) {
            return ValidationResult(false, "Path contains directory traversal attempts")
        }

        // Check for suspicious file extensions
        val extension = path.substringAfterLast('.', "").lowercase()
        if (extension in setOf("exe", "dll", "bat", "cmd", "sh", "php", "asp", "aspx", "jsp")) {
            return ValidationResult(false, "Suspicious file extension detected")
        }

        return ValidationResult(true, "Path is valid")
    }

    fun validateAndSanitize(urlString: String): Pair<ValidationResult, String> {
        val validationResult = validateUrl(urlString)
        if (!validationResult.isValid) {
            return Pair(validationResult, urlString)
        }

        try {
            val url = URL(urlString)
            val sanitizedUrl = buildString {
                append(url.protocol)
                append("://")
                append(url.host)
                if (url.port != -1) {
                    append(":")
                    append(url.port)
                }
                append(url.path.replace(" ", "%20"))
                if (url.query != null) {
                    append("?")
                    append(url.query.replace(" ", "%20"))
                }
            }
            return Pair(ValidationResult(true, "URL is valid and sanitized"), sanitizedUrl)
        } catch (e: MalformedURLException) {
            return Pair(ValidationResult(false, "Failed to sanitize URL: ${e.message}"), urlString)
        }
    }
} 