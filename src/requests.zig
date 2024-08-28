const std = @import("std");
const requests = @This();
const print = std.debug.print;

// TODO: requests.Options
// * stream
// * hooks
// * verify
// * cert
// * proxies

// TODO: requests.Response
// * raw (when stream=True)
// * iterContent
// * isRedirect
// * isPermanentRedirect
// * getNext
// * getLinks

// FUTURE TODO:
// * Add timeout in requests.Options
// * Add a Session object
//      * prepareRequest(prev_req, new_req)
//          * Set up cookie jar
//          * Merge with headers, params, auth, cookies, and hooks
//      * mergeEnvironmentSettings(prev_req, ...)
//          * Merge with proxies, stream, verify, and cert
//      * Set timeout and allow_redirects
//      * After send, get the history
// * Make the json option an object instead of a []const u8

pub const Options = struct {
    headers: []const std.http.Header = &.{},
    data: ?[]const u8 = null,
    json: ?[]const u8 = null,
    max_redirects: u16 = 3,
    file_field: ?requests.FileField = null,
    auth: ?requests.BasicAuth = null,
    params: []const requests.QueryParameter = &.{},
    cookies: []const requests.Cookie = &.{},
};

pub const FileField = struct {
    name: []const u8,
    file_name: []const u8,
    fs: *std.fs.File,
    content_disposition: []const u8 = "form-data",
    content_type: ?[]const u8 = null,
    content_location: ?[]const u8 = null,
};

pub const BasicAuth = struct {
    username: []const u8,
    password: []const u8,
};

pub const QueryParameter = struct {
    name: []const u8,
    value: []const u8,
};

pub const Cookie = struct {
    name: []const u8,
    value: []const u8,
};

pub const Response = struct {
    allocator: std.mem.Allocator = undefined,
    version: std.http.Version = undefined,
    status_code: std.http.Status = undefined,
    keep_alive: bool = undefined,
    headers: std.BufMap = undefined,
    elapsed_time_nanoseconds: i128 = undefined,
    url: []u8 = &.{},
    body: []u8 = &.{},

    pub fn isOk(self: *const requests.Response) bool {
        const status_code = @intFromEnum(self.status_code);
        return (status_code >= 200 and status_code <= 299);
    }

    pub fn saveBodyToFile(self: *const requests.Response, file_name: []const u8) !void {
        var file = try std.fs.cwd().createFile(file_name, .{});
        defer file.close();

        try file.writeAll(self.body);
    }

    pub fn elapsedTimeSeconds(self: *const requests.Response) i64 {
        return @as(i64, @intCast(@divFloor(self.elapsed_time_nanoseconds, std.time.ns_per_s)));
    }

    pub fn elapsedTimeMicroSeconds(self: *const requests.Response) i64 {
        return @as(i64, @intCast(@divFloor(self.elapsed_time_nanoseconds, std.time.ns_per_ms)));
    }

    pub fn deinit(self: *requests.Response) void {
        self.allocator.free(self.url);
        self.allocator.free(self.body);
        self.headers.deinit();
    }
};

pub fn get(allocator: std.mem.Allocator, url: []const u8, options: requests.Options) !requests.Response {
    return try makeRequest(allocator, std.http.Method.GET, url, &options);
}

pub fn post(allocator: std.mem.Allocator, url: []const u8, options: requests.Options) !requests.Response {
    return try makeRequest(allocator, std.http.Method.POST, url, &options);
}

pub fn put(allocator: std.mem.Allocator, url: []const u8, options: requests.Options) !requests.Response {
    return try makeRequest(allocator, std.http.Method.PUT, url, &options);
}

pub fn delete(allocator: std.mem.Allocator, url: []const u8, options: requests.Options) !requests.Response {
    return try makeRequest(allocator, std.http.Method.DELETE, url, &options);
}

const Resources = struct {
    allocator: std.mem.Allocator = undefined,
    arena: std.mem.Allocator = undefined,

    query_string: ?[]u8 = null,
    file_body: ?[]u8 = null,
    cookie_header_value: ?[]u8 = null,

    headers: std.ArrayListAligned(std.http.Header, null) = undefined,

    pub fn init(allocator: std.mem.Allocator, arena: std.mem.Allocator) Resources {
        var self: Resources = Resources{};

        self.allocator = allocator;
        self.arena = arena;

        self.headers = std.ArrayList(std.http.Header).init(self.allocator);

        return self;
    }

    // TODO: Maybe use a std.StringHashMap
    pub fn appendHeader(self: *Resources, name: []const u8, value: []const u8) !void {
        for (self.headers.items) |*header| {
            if (std.mem.eql(u8, header.name, name)) {
                header.value = value;
                return;
            }
        }

        try self.headers.append(.{ .name = name, .value = value });
    }

    pub fn appendHeaders(self: *Resources, headers: []const std.http.Header) !void {
        for (headers) |header| {
            try self.appendHeader(header.name, header.value);
        }
    }

    pub fn buildQueryString(self: *Resources, params: []const requests.QueryParameter) !void {
        var query_string_builder = std.ArrayList(u8).init(self.allocator);
        defer query_string_builder.deinit();

        try query_string_builder.appendSlice(params[0].name);
        try query_string_builder.appendSlice("=");
        try query_string_builder.appendSlice(params[0].value);

        for (params[1..]) |param| {
            try query_string_builder.appendSlice("&");
            try query_string_builder.appendSlice(param.name);
            try query_string_builder.appendSlice("=");
            try query_string_builder.appendSlice(param.value);
        }

        self.query_string = try query_string_builder.toOwnedSlice();
    }

    pub fn buildMultipartFileRequest(self: *Resources, file_field: *const FileField) !void {
        const boundary: [32]u8 = self.get_boundary();

        const content_type_value: []u8 = try std.fmt.allocPrint(self.arena, "multipart/form-data; boundary={s}", .{boundary});
        try self.appendHeader("Content-Type", content_type_value);

        var file_body_builder = std.ArrayList(u8).init(self.allocator);
        defer file_body_builder.deinit();

        const starting_boundary: []u8 = try std.fmt.allocPrint(self.arena, "--{s}\r\n", .{boundary});
        try file_body_builder.appendSlice(starting_boundary);
        self.arena.free(starting_boundary);

        try file_body_builder.appendSlice("Content-Disposition: ");
        const content_disposition: []u8 = try std.fmt.allocPrint(self.arena, "{s}; name=\"{s}\"; filename=\"{s}\"", .{ file_field.content_disposition, file_field.name, file_field.file_name });
        try file_body_builder.appendSlice(content_disposition);
        self.arena.free(content_disposition);
        try file_body_builder.appendSlice("\r\n");

        if (file_field.content_type) |content_type| {
            try file_body_builder.appendSlice("Content-Type: ");
            try file_body_builder.appendSlice(content_type);
            try file_body_builder.appendSlice("\r\n");
        }

        if (file_field.content_location) |content_location| {
            try file_body_builder.appendSlice("Content-Location: ");
            try file_body_builder.appendSlice(content_location);
            try file_body_builder.appendSlice("\r\n");
        }

        try file_body_builder.appendSlice("\r\n");

        try self.readFile(&file_body_builder, file_field.fs);
        try file_body_builder.appendSlice("\r\n");

        const ending_boundary: []u8 = try std.fmt.allocPrint(self.arena, "--{s}--\r\n", .{boundary});
        try file_body_builder.appendSlice(ending_boundary);
        self.arena.free(ending_boundary);

        self.file_body = try file_body_builder.toOwnedSlice();
    }

    pub fn setCookieHeader(self: *Resources, cookies: []const requests.Cookie) !void {
        var cookie_value_builder = std.ArrayList(u8).init(self.allocator);
        defer cookie_value_builder.deinit();

        try cookie_value_builder.appendSlice(cookies[0].name);
        try cookie_value_builder.appendSlice("=");
        try cookie_value_builder.appendSlice(cookies[0].value);

        for (cookies[1..]) |cookie| {
            try cookie_value_builder.appendSlice("; ");
            try cookie_value_builder.appendSlice(cookie.name);
            try cookie_value_builder.appendSlice("=");
            try cookie_value_builder.appendSlice(cookie.value);
        }

        self.cookie_header_value = try cookie_value_builder.toOwnedSlice();
        try self.appendHeader("Cookie", self.cookie_header_value.?);
    }

    pub fn deinit(self: *Resources) void {
        if (self.query_string) |qs| self.allocator.free(qs);
        if (self.file_body) |fb| self.allocator.free(fb);
        if (self.cookie_header_value) |chv| self.allocator.free(chv);
        self.headers.deinit();
    }

    fn get_boundary(_: *Resources) [32]u8 {
        var prng: std.Random.Xoshiro256 = std.Random.DefaultPrng.init(@intCast(std.time.nanoTimestamp()));
        const rand: std.Random = prng.random();

        var bytes: [16]u8 = undefined;

        for (&bytes) |*byte| {
            byte.* = rand.intRangeAtMost(u8, 0, 255);
        }

        const hexChars = "0123456789ABCDEF";
        var boundary: [32]u8 = undefined;

        for (bytes, 0..) |byte, i| {
            boundary[i * 2] = hexChars[byte >> 4];
            boundary[i * 2 + 1] = hexChars[byte & 0x0F];
        }

        return boundary;
    }

    fn readFile(_: *Resources, file_body: *std.ArrayListAligned(u8, null), file: *std.fs.File) !void {
        const file_size: u64 = try file.getEndPos();
        const buffer = try file_body.addManyAsSlice(file_size);

        _ = try file.read(buffer);
    }
};

fn makeRequest(allocator: std.mem.Allocator, method: std.http.Method, url: []const u8, options: *const requests.Options) !requests.Response {
    var client: std.http.Client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var parsed_uri: std.Uri = try std.Uri.parse(url);

    if (options.auth) |auth| {
        parsed_uri.user = std.Uri.Component{ .percent_encoded = auth.username };
        parsed_uri.password = std.Uri.Component{ .percent_encoded = auth.password };
    }

    var buffer: [1024]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = std.heap.FixedBufferAllocator.init(&buffer);
    const arena: std.mem.Allocator = fba.allocator();

    var request_resources: requests.Resources = requests.Resources.init(allocator, arena);
    defer request_resources.deinit();

    if (options.params.len > 0) {
        try request_resources.buildQueryString(options.params);
        parsed_uri.query = std.Uri.Component{ .percent_encoded = request_resources.query_string.? };
    }

    var response_header_buffer: [16 * 1024]u8 = undefined;
    const client_request_options = std.http.Client.RequestOptions{ .server_header_buffer = &response_header_buffer, .redirect_behavior = @enumFromInt(options.max_redirects) };

    var client_request: std.http.Client.Request = try client.open(method, parsed_uri, client_request_options);
    defer client_request.deinit();

    try request_resources.appendHeaders(options.headers);

    // TODO: List of files
    if (options.file_field) |file_field| {
        try request_resources.buildMultipartFileRequest(&file_field);
        client_request.transfer_encoding = .{ .content_length = request_resources.file_body.?.len };
    } else if (options.json) |json_body| {
        client_request.transfer_encoding = .{ .content_length = json_body.len };
        try request_resources.appendHeader("Content-Type", "application/json");
    } else if (options.data) |text_body| {
        client_request.transfer_encoding = .{ .content_length = text_body.len };
    }

    if (options.cookies.len > 0) {
        try request_resources.setCookieHeader(options.cookies);
    }

    client_request.extra_headers = request_resources.headers.items;

    const start: i128 = std.time.nanoTimestamp();

    try client_request.send();

    if (options.file_field != null) {
        try client_request.writeAll(request_resources.file_body.?);
    } else if (options.json) |json_body| {
        try client_request.writeAll(json_body);
    } else if (options.data) |text_body| {
        try client_request.writeAll(text_body);
    }

    try client_request.finish();
    try client_request.wait();

    const end: i128 = std.time.nanoTimestamp() - start;

    return try initResponseFromRequest(allocator, &client_request, end);
}

fn initResponseFromRequest(allocator: std.mem.Allocator, client_request: *std.http.Client.Request, elapsed_time_nanoseconds: i128) !requests.Response {
    var response: requests.Response = requests.Response{
        .allocator = allocator,
        .headers = std.BufMap.init(allocator),
        .elapsed_time_nanoseconds = elapsed_time_nanoseconds,
    };

    var it = client_request.response.iterateHeaders();

    while (it.next()) |header| {
        try response.headers.put(header.name, header.value);
    }

    response.version = client_request.response.version;
    response.status_code = client_request.response.status;
    response.keep_alive = client_request.response.keep_alive;

    var response_url = std.ArrayList(u8).init(response.allocator);
    defer response_url.deinit();

    try client_request.uri.format("", .{}, response_url.writer());

    response.url = try response_url.toOwnedSlice();

    try setResponseBody(&response, client_request);

    return response;
}

fn setResponseBody(response: *requests.Response, client_request: *std.http.Client.Request) !void {
    // TODO: Idk if this is a good idea...
    var temp_body_buffer: [1024]u8 = undefined;

    var body_buffer = std.ArrayList(u8).init(response.allocator);
    defer body_buffer.deinit();

    while (true) {
        const bytes_read = try client_request.read(&temp_body_buffer);

        if (bytes_read == 0) {
            break;
        }

        try body_buffer.appendSlice(temp_body_buffer[0..bytes_read]);
    }

    response.body = try body_buffer.toOwnedSlice();
}
