const std = @import("std");
const root = @import("./root.zig");
const stdout = std.io.getStdOut().writer();

const CommandType = enum { help, text, file, unknown };

fn get_command_type(argument: []const u8) CommandType {
    if (std.mem.eql(u8, argument, "-h") or std.mem.eql(u8, argument, "--help")) return CommandType.help;
    if (std.mem.eql(u8, argument, "--text")) return CommandType.text;
    if (std.mem.eql(u8, argument, "--file")) return CommandType.file;
    return CommandType.unknown;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // get command line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // check if we have enough params
    if (args.len < 2) {
        try print_help();
        return;
    }

    const command = get_command_type(args[1]);

    switch (command) {
        .help => {
            try print_help();
        },
        .file => {
            if (args.len < 3) {
                std.debug.print("Please provide file path", .{});
                return;
            }

            try handle_file(args[2], allocator);
        },
        .text => {
            if (args.len < 3) {
                std.debug.print("Please provide text", .{});
                return;
            }

            try handle_text(args[2], allocator);
        },
        .unknown => {
            try print_help();
        },
    }
}

fn print_help() !void {
    const help_text =
        \\Usage:
        \\  --text <text>    Encode text (e.g., base64-zig --text "hello its gxanshu")
        \\  --file <path>    Encode file (e.g., base64-zig --file "/home/user/file.pdf")
        \\  -h              Show this help message
        \\
    ;

    try stdout.print("{s}\n", .{help_text});
}

fn handle_file(file_path: []const u8, allocator: std.mem.Allocator) !void {
    const file = try std.fs.openFileAbsolute(file_path, .{ .mode = .read_only });
    defer file.close();

    // get file size
    const stat = try file.metadata();
    const fileSize = stat.size();

    // allocate memory
    const content = try allocator.alloc(u8, fileSize);
    defer allocator.free(content);

    _ = try file.readAll(content);

    const base64 = root.Base64.init();
    const encoded_text = try base64.encode(content, allocator);
    defer allocator.free(encoded_text);

    try stdout.print("{s}\n", .{encoded_text});
}

fn handle_text(text: []const u8, allocator: std.mem.Allocator) !void {
    if (text.len == 0) {
        std.debug.print("Please provide text", .{});
        return;
    }

    const base64 = root.Base64.init();
    const encoded_text = try base64.encode(text, allocator);
    defer allocator.free(encoded_text);
    try stdout.print("{s}\n", .{encoded_text});
}
