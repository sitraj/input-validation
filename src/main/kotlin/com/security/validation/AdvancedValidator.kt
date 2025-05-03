package com.security.validation

import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException
import java.util.UUID
import java.util.regex.Pattern

class AdvancedValidator {
    companion object {
        private val IPV4_PATTERN = Pattern.compile(
            "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        )
        
        private val IPV6_PATTERN = Pattern.compile(
            "^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|" +
            "^([0-9a-fA-F]{1,4}:){1,7}:|" +
            "^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|" +
            "^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$|" +
            "^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$|" +
            "^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$|" +
            "^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$|" +
            "^[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})$|" +
            "^:((:[0-9a-fA-F]{1,4}){1,7}|:)$"
        )

        private val UUID_PATTERN = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
        )
    }

    fun validateDate(date: String, format: String = "yyyy-MM-dd"): ValidationResult {
        return try {
            val formatter = DateTimeFormatter.ofPattern(format)
            LocalDate.parse(date, formatter)
            ValidationResult(true, "Date is valid")
        } catch (e: DateTimeParseException) {
            ValidationResult(false, "Invalid date format. Expected format: $format")
        }
    }

    fun validateIPAddress(ip: String): ValidationResult {
        return when {
            IPV4_PATTERN.matcher(ip).matches() -> ValidationResult(true, "Valid IPv4 address")
            IPV6_PATTERN.matcher(ip).matches() -> ValidationResult(true, "Valid IPv6 address")
            else -> ValidationResult(false, "Invalid IP address format")
        }
    }

    fun validateUUID(uuid: String, version: Int = 4): ValidationResult {
        if (!UUID_PATTERN.matcher(uuid).matches()) {
            return ValidationResult(false, "Invalid UUID format")
        }

        return try {
            val parsedUUID = UUID.fromString(uuid)
            val uuidVersion = (parsedUUID.version() and 0x0f).toInt()
            
            when (version) {
                4 -> {
                    if (uuidVersion == 4) {
                        ValidationResult(true, "Valid UUIDv4")
                    } else {
                        ValidationResult(false, "Not a UUIDv4")
                    }
                }
                6 -> {
                    if (uuidVersion == 6) {
                        ValidationResult(true, "Valid UUIDv6")
                    } else {
                        ValidationResult(false, "Not a UUIDv6")
                    }
                }
                else -> ValidationResult(false, "Unsupported UUID version")
            }
        } catch (e: IllegalArgumentException) {
            ValidationResult(false, "Invalid UUID format")
        }
    }
} 