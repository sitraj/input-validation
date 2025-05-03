package com.security.validation

import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.util.zip.ZipFile

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
        private const val MAX_FILENAME_LENGTH = 255
        private val FORBIDDEN_FILENAME_CHARS = setOf('/', '\\', ':', '*', '?', '"', '<', '>', '|')
    }

    fun validateFile(file: File): ValidationResult {
        if (!file.exists()) {
            return ValidationResult(false, "File does not exist")
        }
        if (!file.isFile) {
            return ValidationResult(false, "Path is not a file")
        }
        if (!file.canRead()) {
            return ValidationResult(false, "File is not readable")
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
        if (extension.isEmpty()) {
            return ValidationResult(false, "File must have an extension")
        }
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
            // Check for Mach-O header (macOS executables)
            if (bytes.size >= 4 && bytes[0] == 0xCF.toByte() && bytes[1] == 0xFA.toByte() &&
                bytes[2] == 0xED.toByte() && bytes[3] == 0xFE.toByte()) {
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
        if (path.length > MAX_FILENAME_LENGTH) {
            return ValidationResult(false, "Path length exceeds maximum limit of $MAX_FILENAME_LENGTH characters")
        }
        if (FORBIDDEN_FILENAME_CHARS.any { path.contains(it) }) {
            return ValidationResult(false, "Path contains forbidden characters")
        }
        return ValidationResult(true, "Path is valid")
    }

    fun validateZipFile(file: File): ValidationResult {
        if (!file.extension.equals("zip", ignoreCase = true)) {
            return ValidationResult(false, "File is not a ZIP archive")
        }
        try {
            ZipFile(file).use { zip ->
                val entries = zip.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    if (entry.isDirectory) {
                        continue
                    }
                    if (entry.size > MAX_FILE_SIZE) {
                        return ValidationResult(false, "ZIP contains file exceeding size limit")
                    }
                    val entryPath = entry.name
                    if (entryPath.contains("..") || entryPath.contains("/") || entryPath.contains("\\")) {
                        return ValidationResult(false, "ZIP contains files with invalid paths")
                    }
                }
            }
            return ValidationResult(true, "ZIP file is valid")
        } catch (e: Exception) {
            return ValidationResult(false, "Invalid ZIP file: ${e.message}")
        }
    }
} 