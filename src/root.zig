const std = @import("std");
const expect = std.testing.expect;

/// Calculates the required length of a base64 encoded string given input bytes
/// Returns length in bytes needed to store the base64 encoded string
fn calc_encode_length(input_bytes: []const u8) usize {
    if (input_bytes.len < 3) return 4;
    const estimated_output_length: usize = (@intFromFloat(@ceil(@as(f64, @floatFromInt(input_bytes.len)) / 3.0)));
    return estimated_output_length * 4;
}

/// Calculates the length of the original data from base64 encoded input
/// Returns error if input length is invalid (not multiple of 4)
/// Returns length in bytes needed to store the decoded data
fn calc_decode_length(input_bytes: []const u8) !usize {
    if (input_bytes.len == 0) return 0;
    if (input_bytes.len % 4 != 0) return error.InvalidLength;

    var padding_count: usize = 0;
    if (input_bytes[input_bytes.len - 1] == '=') padding_count += 1;
    if (input_bytes.len > 1 and input_bytes[input_bytes.len - 2] == '=') padding_count += 1;

    return (input_bytes.len / 4) * 3 - padding_count;
}

/// Base64 encoding/decoding
pub const Base64 = struct {
    /// Table containing the base64 alphabet characters
    encoding_table: []const u8,

    /// Initialize a new Base64 encoder/decoder with standard alphabet
    pub fn init() Base64 {
        return Base64{
            .encoding_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        };
    }

    /// Get the base64 character at given position in encoding table
    fn char_at(self: Base64, position: u8) u8 {
        return self.encoding_table[position];
    }

    /// Find the index of a base64 character in the encoding table
    /// Returns error.InvalidCharacter if character not found
    fn char_index(self: Base64, character: u8) !u8 {
        if (character == '=') return 0;

        for (self.encoding_table, 0..) |current_char, index| {
            if (current_char == character) return @as(u8, @intCast(index));
        }

        return error.InvalidCharacter;
    }

    /// Encode raw bytes into base64 string
    /// Returns allocated buffer containing the base64 encoded string
    pub fn encode(self: Base64, input_bytes: []const u8, allocator: std.mem.Allocator) ![]u8 {
        if (input_bytes.len == 0) return &[_]u8{};

        const required_length = calc_encode_length(input_bytes);
        var encoded_buffer = try allocator.alloc(u8, required_length);
        var write_position: usize = 0;

        // Process input bytes in groups of 3, generating 4 output bytes
        var read_position: usize = 0;
        while (read_position + 3 <= input_bytes.len) : (read_position += 3) {
            encoded_buffer[write_position] = self.char_at(input_bytes[read_position] >> 2);
            encoded_buffer[write_position + 1] = self.char_at(((input_bytes[read_position] & 0x03) << 4) | (input_bytes[read_position + 1] >> 4));
            encoded_buffer[write_position + 2] = self.char_at(((input_bytes[read_position + 1] & 0x0F) << 2) | (input_bytes[read_position + 2] >> 6));
            encoded_buffer[write_position + 3] = self.char_at(input_bytes[read_position + 2] & 0x3F);
            write_position += 4;
        }

        // Handle remaining bytes with padding
        if (read_position < input_bytes.len) {
            encoded_buffer[write_position] = self.char_at(input_bytes[read_position] >> 2);
            if (read_position + 1 == input_bytes.len) {
                encoded_buffer[write_position + 1] = self.char_at((input_bytes[read_position] & 0x03) << 4);
                encoded_buffer[write_position + 2] = '=';
                encoded_buffer[write_position + 3] = '=';
            } else {
                encoded_buffer[write_position + 1] = self.char_at(((input_bytes[read_position] & 0x03) << 4) | (input_bytes[read_position + 1] >> 4));
                encoded_buffer[write_position + 2] = self.char_at((input_bytes[read_position + 1] & 0x0F) << 2);
                encoded_buffer[write_position + 3] = '=';
            }
        }

        return encoded_buffer;
    }

    /// Decode base64 string back to original bytes
    /// Returns allocated buffer containing the decoded data
    pub fn decode(self: Base64, input_bytes: []const u8, allocator: std.mem.Allocator) ![]u8 {
        if (input_bytes.len == 0) return &[_]u8{};

        const required_length = try calc_decode_length(input_bytes);
        var decoded_buffer = try allocator.alloc(u8, required_length);
        var write_position: usize = 0;

        // Process input in groups of 4 base64 chars, generating 3 output bytes
        var read_position: usize = 0;
        while (read_position + 4 <= input_bytes.len) : (read_position += 4) {
            const byte1 = try self.char_index(input_bytes[read_position]);
            const byte2 = try self.char_index(input_bytes[read_position + 1]);
            const byte3 = try self.char_index(input_bytes[read_position + 2]);
            const byte4 = try self.char_index(input_bytes[read_position + 3]);

            decoded_buffer[write_position] = (byte1 << 2) | (byte2 >> 4);
            if (input_bytes[read_position + 2] != '=') {
                decoded_buffer[write_position + 1] = (byte2 << 4) | (byte3 >> 2);
                if (input_bytes[read_position + 3] != '=') {
                    decoded_buffer[write_position + 2] = (byte3 << 6) | byte4;
                }
            }
            write_position += 3;
        }

        return decoded_buffer;
    }
};

test "encode length" {
    try expect(calc_encode_length("") == 4);
    try expect(calc_encode_length("f") == 4);
    try expect(calc_encode_length("fo") == 4);
    try expect(calc_encode_length("foo") == 4);
    try expect(calc_encode_length("foob") == 8);
    try expect(calc_encode_length("fooba") == 8);
    try expect(calc_encode_length("foobar") == 8);
}

test "decode length" {
    try expect(try calc_decode_length("") == 0);
    try expect(try calc_decode_length("Zg==") == 1);
    try expect(try calc_decode_length("Zm8=") == 2);
    try expect(try calc_decode_length("Zm9v") == 3);
    try expect(try calc_decode_length("Zm9vYg==") == 4);
    try expect(try calc_decode_length("Zm9vYmE=") == 5);
    try expect(try calc_decode_length("Zm9vYmFy") == 6);
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
