const std = @import("std");
const expect = std.testing.expect;

/// Calculates the required length of a base64 encoded string given input bytes
/// Returns length in bytes needed to store the base64 encoded string
fn calcEncodeLength(input_bytes: []const u8) usize {
    if (input_bytes.len < 3) return 4;
    const estimatedOutputLength: usize = (@intFromFloat(@ceil(@as(f64, @floatFromInt(input_bytes.len)) / 3.0)));
    return estimatedOutputLength * 4;
}

/// Calculates the length of the original data from base64 encoded input
/// Returns error if input length is invalid (not multiple of 4)
/// Returns length in bytes needed to store the decoded data
fn calcDecodeLength(input_bytes: []const u8) !usize {
    if (input_bytes.len == 0) return 0;
    if (input_bytes.len % 4 != 0) return error.InvalidLength;

    var paddingCount: usize = 0;
    if (input_bytes[input_bytes.len - 1] == '=') paddingCount += 1;
    if (input_bytes.len > 1 and input_bytes[input_bytes.len - 2] == '=') paddingCount += 1;

    return (input_bytes.len / 4) * 3 - paddingCount;
}

/// Base64 encoding/decoding
pub const Base64 = struct {
    /// Table containing the base64 alphabet characters
    encodingTable: []const u8,

    /// Initialize a new Base64 encoder/decoder with standard alphabet
    pub fn init() Base64 {
        return Base64{
            .encodingTable = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        };
    }

    /// Get the base64 character at given position in encoding table
    fn charAt(self: Base64, position: u8) u8 {
        return self.encodingTable[position];
    }

    /// Find the index of a base64 character in the encoding table
    /// Returns error.InvalidCharacter if character not found
    fn charIndex(self: Base64, character: u8) !u8 {
        if (character == '=') return 0;

        for (self.encodingTable, 0..) |currentChar, index| {
            if (currentChar == character) return @as(u8, @intCast(index));
        }

        return error.InvalidCharacter;
    }

    /// Encode raw bytes into base64 string
    /// Returns allocated buffer containing the base64 encoded string
    pub fn encode(self: Base64, input_bytes: []const u8, allocator: std.mem.Allocator) ![]u8 {
        if (input_bytes.len == 0) return &[_]u8{};

        const requiredLength = calcEncodeLength(input_bytes);
        var encodedBuffer = try allocator.alloc(u8, requiredLength);
        var writePosition: usize = 0;

        // Process input bytes in groups of 3, generating 4 output bytes
        var readPosition: usize = 0;
        while (readPosition + 3 <= input_bytes.len) : (readPosition += 3) {
            encodedBuffer[writePosition] = self.charAt(input_bytes[readPosition] >> 2);
            encodedBuffer[writePosition + 1] = self.charAt(((input_bytes[readPosition] & 0x03) << 4) | (input_bytes[readPosition + 1] >> 4));
            encodedBuffer[writePosition + 2] = self.charAt(((input_bytes[readPosition + 1] & 0x0F) << 2) | (input_bytes[readPosition + 2] >> 6));
            encodedBuffer[writePosition + 3] = self.charAt(input_bytes[readPosition + 2] & 0x3F);
            writePosition += 4;
        }

        // Handle remaining bytes with padding
        if (readPosition < input_bytes.len) {
            encodedBuffer[writePosition] = self.charAt(input_bytes[readPosition] >> 2);
            if (readPosition + 1 == input_bytes.len) {
                encodedBuffer[writePosition + 1] = self.charAt((input_bytes[readPosition] & 0x03) << 4);
                encodedBuffer[writePosition + 2] = '=';
                encodedBuffer[writePosition + 3] = '=';
            } else {
                encodedBuffer[writePosition + 1] = self.charAt(((input_bytes[readPosition] & 0x03) << 4) | (input_bytes[readPosition + 1] >> 4));
                encodedBuffer[writePosition + 2] = self.charAt((input_bytes[readPosition + 1] & 0x0F) << 2);
                encodedBuffer[writePosition + 3] = '=';
            }
        }

        return encodedBuffer;
    }

    /// Decode base64 string back to original bytes
    /// Returns allocated buffer containing the decoded data
    pub fn decode(self: Base64, input_bytes: []const u8, allocator: std.mem.Allocator) ![]u8 {
        if (input_bytes.len == 0) return &[_]u8{};

        const requiredLength = try calcDecodeLength(input_bytes);
        var decodedBuffer = try allocator.alloc(u8, requiredLength);
        var writePosition: usize = 0;

        // Process input in groups of 4 base64 chars, generating 3 output bytes
        var readPosition: usize = 0;
        while (readPosition + 4 <= input_bytes.len) : (readPosition += 4) {
            const byte1 = try self.charIndex(input_bytes[readPosition]);
            const byte2 = try self.charIndex(input_bytes[readPosition + 1]);
            const byte3 = try self.charIndex(input_bytes[readPosition + 2]);
            const byte4 = try self.charIndex(input_bytes[readPosition + 3]);

            decodedBuffer[writePosition] = (byte1 << 2) | (byte2 >> 4);
            if (input_bytes[readPosition + 2] != '=') {
                decodedBuffer[writePosition + 1] = (byte2 << 4) | (byte3 >> 2);
                if (input_bytes[readPosition + 3] != '=') {
                    decodedBuffer[writePosition + 2] = (byte3 << 6) | byte4;
                }
            }
            writePosition += 3;
        }

        return decodedBuffer;
    }
};

test "encode length" {
    try expect(calcEncodeLength("") == 4);
    try expect(calcEncodeLength("f") == 4);
    try expect(calcEncodeLength("fo") == 4);
    try expect(calcEncodeLength("foo") == 4);
    try expect(calcEncodeLength("foob") == 8);
    try expect(calcEncodeLength("fooba") == 8);
    try expect(calcEncodeLength("foobar") == 8);
}

test "decode length" {
    try expect(try calcDecodeLength("") == 0);
    try expect(try calcDecodeLength("Zg==") == 1);
    try expect(try calcDecodeLength("Zm8=") == 2);
    try expect(try calcDecodeLength("Zm9v") == 3);
    try expect(try calcDecodeLength("Zm9vYg==") == 4);
    try expect(try calcDecodeLength("Zm9vYmE=") == 5);
    try expect(try calcDecodeLength("Zm9vYmFy") == 6);
}

test "encode decode" {
    const allocator = std.heap.page_allocator;
    const base64 = Base64.init();

    const test_strings = [_][]const u8{
        "",
        "f",
        "fo",
        "foo",
        "foob",
        "fooba",
        "foobar",
        "Hello World!",
    };

    for (test_strings) |test_str| {
        const encoded = try base64.encode(test_str, allocator);
        defer allocator.free(encoded);
        const decoded = try base64.decode(encoded, allocator);
        defer allocator.free(decoded);
        try expect(std.mem.eql(u8, test_str, decoded));
    }
}
