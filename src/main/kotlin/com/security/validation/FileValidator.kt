package com.security.validation

import java.io.File
import java.nio.file.Files
import java.nio.file.Path

class FileValidator {
    companion object {
        private val ALLOWED_EXTENSIONS = setOf("jpg", "jpeg", "png", "gif", "pdf", "txt", "doc", "docx")
        private val ALLOWED_MIME_TYPES = setOf(
            "image/jpeg", "image/png", "image/gif",
            "application/pdf", "text/plain",
            "application/msword",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        )
        private const val MAX_FILE_SIZE: Long = 10L * 1024L * 1024L // 10MB
    }

    fun validateFile(file: File): ValidationResult {
        if (!file.exists()) {
            return ValidationResult(false, "File does not exist")
        }
        if (!file.isFile) {
            return ValidationResult(false, "Path is not a file")
        }
        return ValidationResult(true, "File is valid")
    }

    fun validateFileSize(file: File, maxSize: Long = MAX_FILE_SIZE): ValidationResult {
        if (file.length() > maxSize) {
            return ValidationResult(false, "File size exceeds maximum limit of ${maxSize / 1024L / 1024L}MB")
        }
        return ValidationResult(true, "File size is within limits")
    }

    fun validateFileExtension(file: File, allowedExtensions: Set<String> = ALLOWED_EXTENSIONS): ValidationResult {
        val extension = file.extension.lowercase()
        if (!allowedExtensions.contains(extension)) {
            return ValidationResult(false, "File extension '$extension' is not allowed")
        }
        return ValidationResult(true, "File extension is allowed")
    }

    fun validateMimeType(file: File, allowedTypes: Set<String> = ALLOWED_MIME_TYPES): ValidationResult {
        val mimeType = Files.probeContentType(file.toPath())
        if (mimeType == null) {
            return ValidationResult(false, "Could not determine file type")
        }
        if (!allowedTypes.contains(mimeType)) {
            return ValidationResult(false, "File type '$mimeType' is not allowed")
        }
        return ValidationResult(true, "File type is allowed")
    }

    fun validateExecutableContent(file: File): ValidationResult {
        try {
            val bytes = file.readBytes().take(4).toByteArray()
            // Check for MZ header (Windows executables)
            if (bytes.size >= 2 && bytes[0] == 0x4D.toByte() && bytes[1] == 0x5A.toByte()) {
                return ValidationResult(false, "File appears to be an executable")
            }
            // Check for ELF header (Linux executables)
            if (bytes.size >= 4 && bytes[0] == 0x7F.toByte() && bytes[1] == 0x45.toByte() &&
                bytes[2] == 0x4C.toByte() && bytes[3] == 0x46.toByte()) {
                return ValidationResult(false, "File appears to be an executable")
            }
            return ValidationResult(true, "File does not appear to be executable")
        } catch (e: Exception) {
            return ValidationResult(false, "Could not check file content: ${e.message}")
        }
    }

    fun validatePath(path: String): ValidationResult {
        val normalizedPath = Path.of(path).normalize().toString()
        if (normalizedPath != path) {
            return ValidationResult(false, "Path contains directory traversal attempts")
        }
        if (normalizedPath.contains("..")) {
            return ValidationResult(false, "Path contains parent directory references")
        }
        return ValidationResult(true, "Path is valid")
    }
} 