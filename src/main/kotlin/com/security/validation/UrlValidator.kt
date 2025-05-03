package com.security.validation

import java.net.URL
import java.net.MalformedURLException
import java.net.InetAddress
import java.util.regex.Pattern

class UrlValidator {
    companion object {
        private val ALLOWED_PROTOCOLS = setOf("http", "https")
        private val BLOCKED_DOMAINS = setOf(
            "localhost", "127.0.0.1", "0.0.0.0", "[::1]",
            "169.254.169.254", // AWS metadata endpoint
            "metadata.google.internal", // GCP metadata endpoint
            "169.254.169.253", // Azure metadata endpoint
            "169.254.169.254", // DigitalOcean metadata endpoint
            "metadata.azure.internal" // Azure metadata endpoint
        )
        private val INTERNAL_IP_PATTERNS = listOf(
            "^10\\.",
            "^172\\.(1[6-9]|2[0-9]|3[0-1])\\.",
            "^192\\.168\\.",
            "^169\\.254\\.",
            "^127\\.",
            "^0\\.",
            "^::1$",
            "^fc00::",
            "^fd00::"
        ).map { Regex(it) }

        private val MAX_URL_LENGTH = 2048
        private val MAX_PATH_LENGTH = 1024
        private val MAX_QUERY_LENGTH = 1024
    }

    fun validateUrl(urlString: String): ValidationResult {
        if (urlString.length > MAX_URL_LENGTH) {
            return ValidationResult(false, "URL exceeds maximum length of $MAX_URL_LENGTH characters")
        }

        return try {
            val url = URL(urlString)
            validateProtocol(url)
                .takeIf { it.isValid }
                ?.let { validateDomain(url) }
                ?.takeIf { it.isValid }
                ?.let { validatePath(url) }
                ?.takeIf { it.isValid }
                ?.let { validateQuery(url) }
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

        // Resolve IP address and check if it's internal
        try {
            val ip = InetAddress.getByName(host)
            if (ip.isLoopbackAddress || ip.isLinkLocalAddress || ip.isSiteLocalAddress) {
                return ValidationResult(false, "Domain resolves to internal IP address")
            }
        } catch (e: Exception) {
            return ValidationResult(false, "Could not resolve domain: ${e.message}")
        }

        return ValidationResult(true, "Domain is valid")
    }

    private fun validatePath(url: URL): ValidationResult {
        val path = url.path
        
        if (path.length > MAX_PATH_LENGTH) {
            return ValidationResult(false, "Path exceeds maximum length of $MAX_PATH_LENGTH characters")
        }

        // Check for directory traversal
        if (path.contains("../") || path.contains("..\\")) {
            return ValidationResult(false, "Path contains directory traversal attempts")
        }

        // Check for suspicious file extensions
        val extension = path.substringAfterLast('.', "").lowercase()
        if (extension in setOf("exe", "dll", "bat", "cmd", "sh", "php", "asp", "aspx", "jsp", "war", "jar")) {
            return ValidationResult(false, "Suspicious file extension detected")
        }

        return ValidationResult(true, "Path is valid")
    }

    private fun validateQuery(url: URL): ValidationResult {
        val query = url.query ?: return ValidationResult(true, "No query parameters")
        
        if (query.length > MAX_QUERY_LENGTH) {
            return ValidationResult(false, "Query exceeds maximum length of $MAX_QUERY_LENGTH characters")
        }

        // Check for suspicious query parameters
        if (query.contains("password=", ignoreCase = true) ||
            query.contains("token=", ignoreCase = true) ||
            query.contains("secret=", ignoreCase = true) ||
            query.contains("key=", ignoreCase = true)) {
            return ValidationResult(false, "Query contains sensitive parameters")
        }

        return ValidationResult(true, "Query is valid")
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