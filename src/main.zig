const std = @import("std");
const root = @import("./root.zig");
const stdout = std.io.getStdOut().writer();

const CommandType = enum { help, text, file, unknown };

fn getCommandType(argument: []const u8) CommandType {
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
        try printHelp();
        return;
    }

    const command = getCommandType(args[1]);

    switch (command) {
        .help => {
            try printHelp();
        },
        .file => {
            if (args.len < 3) {
                std.debug.print("Please provide file path", .{});
                return;
            }

            try handleFile(args[2], allocator);
        },
        .text => {
            if (args.len < 3) {
                std.debug.print("Please provide text", .{});
                return;
            }

            try handleText(args[2], allocator);
        },
        .unknown => {
            try printHelp();
        },
    }
}

fn printHelp() !void {
    const helpText =
        \\Usage:
        \\  --text <text>    Encode text (e.g., base64-zig --text "hello its gxanshu")
        \\  --file <path>    Encode file (e.g., base64-zig --file "/home/user/file.pdf")
        \\  -h              Show this help message
        \\
    ;

    try stdout.print("{s}\n", .{helpText});
}

fn handleFile(filePath: []const u8, allocator: std.mem.Allocator) !void {
    const file = try std.fs.openFileAbsolute(filePath, .{ .mode = .read_only });
    defer file.close();

    // get file size
    const stat = try file.metadata();
    const fileSize = stat.size();

    // allocate memory
    const content = try allocator.alloc(u8, fileSize);
    defer allocator.free(content);

    _ = try file.readAll(content);

    const base64 = root.Base64.init();
    const encodedText = try base64.encode(content, allocator);
    defer allocator.free(encodedText);

    try stdout.print("{s}\n", .{encodedText});
}

fn handleText(text: []const u8, allocator: std.mem.Allocator) !void {
    if (text.len == 0) {
        std.debug.print("Please provide text", .{});
        return;
    }

    const base64 = root.Base64.init();
    const encodedText = try base64.encode(text, allocator);
    defer allocator.free(encodedText);
    try stdout.print("{s}\n", .{encodedText});
}
