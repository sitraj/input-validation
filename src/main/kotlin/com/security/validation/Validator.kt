package com.security.validation

interface Validator<T> {
    fun validate(input: T): ValidationResult
}

abstract class BaseValidator<T> : Validator<T> {
    protected val validators: MutableList<(T) -> ValidationResult> = mutableListOf()
    
    protected fun addValidator(validator: (T) -> ValidationResult) {
        validators.add(validator)
    }
    
    override fun validate(input: T): ValidationResult {
        val errors = validators.mapNotNull { validator ->
            val result = validator(input)
            if (!result.isValid) result.message else null
        }
        
        return if (errors.isEmpty()) {
            ValidationResult(true, "Input is valid")
        } else {
            ValidationResult(false, errors.joinToString("; "))
        }
    }
} 