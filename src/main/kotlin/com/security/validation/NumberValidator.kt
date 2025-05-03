package com.security.validation

class NumberValidator {
    fun validateNumber(input: Number): ValidationResult {
        val value = input.toDouble()
        return when {
            value.isNaN() -> ValidationResult(false, "Input is not a valid number")
            value.isInfinite() -> ValidationResult(false, "Input is infinite")
            else -> ValidationResult(true, "Input is valid")
        }
    }
    
    fun validateRange(input: Number, min: Number, max: Number): ValidationResult {
        val value = input.toDouble()
        return when {
            value < min.toDouble() -> ValidationResult(false, "Value is less than minimum allowed: $min")
            value > max.toDouble() -> ValidationResult(false, "Value is greater than maximum allowed: $max")
            else -> ValidationResult(true, "Value is within valid range")
        }
    }
    
    fun validatePositive(input: Number): ValidationResult {
        val value = input.toDouble()
        return when {
            value <= 0 -> ValidationResult(false, "Value must be positive")
            else -> ValidationResult(true, "Value is positive")
        }
    }
    
    fun validateInteger(input: Number): ValidationResult {
        val value = input.toDouble()
        return when {
            value != value.toLong().toDouble() -> ValidationResult(false, "Value must be an integer")
            value > Int.MAX_VALUE -> ValidationResult(false, "Value exceeds maximum integer value")
            value < Int.MIN_VALUE -> ValidationResult(false, "Value is below minimum integer value")
            else -> ValidationResult(true, "Value is a valid integer")
        }
    }

    fun validateNonNegative(input: Number): ValidationResult {
        val value = input.toDouble()
        return when {
            value < 0 -> ValidationResult(false, "Value must be non-negative")
            else -> ValidationResult(true, "Value is non-negative")
        }
    }
} 