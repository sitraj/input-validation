package com.security.validation

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource

class AdvancedValidatorTest {
    private val validator = AdvancedValidator()

    @Test
    fun `test valid date format`() {
        val result = validator.validateDate("2024-05-03")
        assertTrue(result.isValid)
        assertEquals("Date is valid", result.message)
    }

    @Test
    fun `test invalid date format`() {
        val result = validator.validateDate("2024/05/03")
        assertFalse(result.isValid)
        assertEquals("Invalid date format. Expected format: yyyy-MM-dd", result.message)
    }

    @Test
    fun `test custom date format`() {
        val result = validator.validateDate("03/05/2024", "dd/MM/yyyy")
        assertTrue(result.isValid)
        assertEquals("Date is valid", result.message)
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "255.255.255.255"
    ])
    fun `test valid IPv4 addresses`(ip: String) {
        val result = validator.validateIPAddress(ip)
        assertTrue(result.isValid)
        assertEquals("Valid IPv4 address", result.message)
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "2001:db8::1",
        "::1",
        "2001:db8:3333:4444:5555:6666:7777:8888"
    ])
    fun `test valid IPv6 addresses`(ip: String) {
        val result = validator.validateIPAddress(ip)
        assertTrue(result.isValid)
        assertEquals("Valid IPv6 address", result.message)
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "256.0.0.1",
        "192.168.1",
        "192.168.1.256",
        "192.168.1.1.1",
        "not.an.ip"
    ])
    fun `test invalid IPv4 addresses`(ip: String) {
        val result = validator.validateIPAddress(ip)
        assertFalse(result.isValid)
        assertEquals("Invalid IP address format", result.message)
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334:1234",
        "2001:db8::1::2",
        "not:an:ipv6",
        "2001:db8:3333:4444:5555:6666:7777:8888:9999"
    ])
    fun `test invalid IPv6 addresses`(ip: String) {
        val result = validator.validateIPAddress(ip)
        assertFalse(result.isValid)
        assertEquals("Invalid IP address format", result.message)
    }

    @Test
    fun `test valid UUIDv4`() {
        val uuid = "550e8400-e29b-41d4-a716-446655440000" // Valid UUIDv4
        val result = validator.validateUUID(uuid, version = 4)
        assertTrue(result.isValid)
        assertEquals("Valid UUIDv4", result.message)
    }

    @Test
    fun `test valid UUIDv6`() {
        val uuid = "1ed4d2e6-74d4-6bd4-9bbd-c3c5b2345678" // Valid UUIDv6
        val result = validator.validateUUID(uuid, version = 6)
        assertTrue(result.isValid)
        assertEquals("Valid UUIDv6", result.message)
    }

    @ParameterizedTest
    @ValueSource(strings = [
        "not-a-uuid",
        "123e4567-e89b-12d3-a456-42661417400", // Too short
        "123e4567-e89b-12d3-a456-4266141740000", // Too long
        "123e4567-e89b-12d3-a456-42661417400g" // Invalid character
    ])
    fun `test invalid UUID format`(uuid: String) {
        val result = validator.validateUUID(uuid)
        assertFalse(result.isValid)
        assertEquals("Invalid UUID format", result.message)
    }

    @Test
    fun `test UUID version mismatch`() {
        val uuid = "550e8400-e29b-41d4-a716-446655440000" // This is a v4 UUID
        val result = validator.validateUUID(uuid, version = 6)
        assertFalse(result.isValid)
        assertEquals("Not a UUIDv6", result.message)
    }

    @Test
    fun `test unsupported UUID version`() {
        val uuid = "550e8400-e29b-41d4-a716-446655440000"
        val result = validator.validateUUID(uuid, version = 5)
        assertFalse(result.isValid)
        assertEquals("Unsupported UUID version", result.message)
    }
} 