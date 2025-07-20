// zig version: 0.14.0
// zig build-exe tumbleweed.zig -lc -OReleaseFast
const std = @import("std");

const stdout = std.io.getStdOut().writer();
const stdin = std.io.getStdIn();
const reader = stdin.reader();

var fba_buf: [128]u8 = undefined;
var fba: std.heap.FixedBufferAllocator = undefined;

var tumbleweed_incubators: [16]?[]u8 = undefined;
var heaps: [4]std.mem.Allocator = undefined;
var burn_count = [4]u8{ 0, 0, 0, 0 };

const technical_difficulty = error.FileNotFound;

fn readNonNegativeInt(upper_limit: isize) !usize {
    var full_buf: [16]u8 = undefined;
    const buf = try reader.readUntilDelimiterOrEof(&full_buf, '\n');

    const input = std.mem.trimRight(u8, buf.?, "\n");

    const parsed_input = std.fmt.parseUnsigned(usize, input, 10) catch {
        try stdout.print("Invalid number.\n", .{});
        return technical_difficulty;
    };

    if (upper_limit <= 0 or parsed_input < upper_limit) {
        return parsed_input;
    } else {
        return technical_difficulty;
    }
}

fn welcome() !void {
    try stdout.print("Welcome to Tumbleweed Inc.!\n", .{});
    try stdout.print("Your job is to make heaps of tumbleweeds, burn some of them, and\n", .{});
    try stdout.print("send those burning fireballs across different heaps to annoy people!\n", .{});
    try stdout.print("Though, you can only set so many of them on fire on each heap before\n", .{});
    try stdout.print("people notice and stop you. Well then, have fun!\n\n", .{});
}

fn printOptions() !void {
    try stdout.print("\nOptions\n", .{});
    try stdout.print("[0] Grow a tumbleweed\n", .{});
    try stdout.print("[1] Set a tumbleweed on fire\n", .{});
    try stdout.print("[2] Inspect a tumbleweed\n", .{});
    try stdout.print("[3] Trim or feed a tumbleweed\n", .{});
    try stdout.print("[4] Give up\n", .{});
    try stdout.print("> ", .{});
}

fn chooseHeap() !usize {
    try stdout.print("Choose heap:\n", .{});
    try stdout.print("[0] C\n", .{});
    try stdout.print("[1] Page\n", .{});
    try stdout.print("[2] SMP\n", .{});
    try stdout.print("[3] Fixed Buffer\n", .{});
    try stdout.print("> ", .{});

    return try readNonNegativeInt(heaps.len);
}

fn grow() !void {
    var idx: usize = undefined;
    var size: usize = undefined;

    try stdout.print("Which incubator? ", .{});
    idx = readNonNegativeInt(tumbleweed_incubators.len) catch {
        try stdout.print("Invalid index!\n", .{});
        return technical_difficulty;
    };

    try stdout.print("Size? ", .{});
    size = readNonNegativeInt(0) catch {
        try stdout.print("Invalid size!\n", .{});
        return technical_difficulty;
    };

    const heap_idx = chooseHeap() catch {
        try stdout.print("Invalid heap choice!\n", .{});
        return technical_difficulty;
    };
    tumbleweed_incubators[idx] = try heaps[heap_idx].alloc(u8, size);

    try stdout.print("Label: ", .{});
    _ = try reader.readUntilDelimiterOrEof(tumbleweed_incubators[idx].?, '\n');
}

fn burn() !void {
    var idx: usize = undefined;

    try stdout.print("Which incubator? ", .{});
    idx = readNonNegativeInt(tumbleweed_incubators.len) catch {
        try stdout.print("Invalid index!\n", .{});
        return technical_difficulty;
    };

    const heap_idx = chooseHeap() catch {
        try stdout.print("Invalid heap choice!\n", .{});
        return technical_difficulty;
    };

    if (burn_count[heap_idx] < 2) {
        burn_count[heap_idx] += 1;
        heaps[heap_idx].free(tumbleweed_incubators[idx].?);
        tumbleweed_incubators[idx] = null;
    }
}

fn inspect() !void {
    var idx: usize = undefined;

    try stdout.print("Which incubator? ", .{});
    idx = readNonNegativeInt(tumbleweed_incubators.len) catch {
        try stdout.print("Invalid index!\n", .{});
        return technical_difficulty;
    };

    try stdout.print("{s}\n", .{tumbleweed_incubators[idx].?});
}

fn resize() !void {
    var idx: usize = undefined;
    var new_size: usize = undefined;

    try stdout.print("Which incubator? ", .{});
    idx = readNonNegativeInt(tumbleweed_incubators.len) catch {
        try stdout.print("Invalid index!\n", .{});
        return technical_difficulty;
    };

    try stdout.print("Target size: ", .{});
    new_size = readNonNegativeInt(0) catch {
        try stdout.print("Invalid size!\n", .{});
        return technical_difficulty;
    };

    const heap_idx = chooseHeap() catch {
        try stdout.print("Invalid heap choice!\n", .{});
        return technical_difficulty;
    };

    if (heaps[heap_idx].resize(tumbleweed_incubators[idx].?, new_size)) {
        try stdout.print("Resize success!\n", .{});
    } else {
        try stdout.print("Resize failed!\n", .{});
    }
}

pub fn main() !void {
    try welcome();

    heaps[0] = std.heap.c_allocator;
    heaps[1] = std.heap.page_allocator;
    heaps[2] = std.heap.smp_allocator;
    fba = std.heap.FixedBufferAllocator.init(&fba_buf);
    heaps[3] = fba.allocator();

    var choice: usize = undefined;

    while (true) {
        try printOptions();

        choice = readNonNegativeInt(5) catch {
            try stdout.print("Invalid choice!\n", .{});
            continue;
        };

        try switch (choice) {
            0 => grow(),
            1 => burn(),
            2 => inspect(),
            3 => resize(),
            else => break,
        };
    }
}
