const pg = @import("pg");
const std = @import("std");
const httpz = @import("httpz");
const print = std.debug.print;

const c = @cImport({
    @cInclude("time.h");
});

//------------------------- BaseModels --------------------------------------

const App = struct {
    pool: *pg.Pool,
    pub fn notFound(_: *App, _: *httpz.Request, res: *httpz.Response) !void {
        res.status = 404;
        res.body = "NOPE!";
    }
    pub fn uncaughtError(_: *App, req: *httpz.Request, res: *httpz.Response, err: anyerror) void {
        std.debug.print("uncaught http error at {s}: {}\n", .{ req.url.path, err });
        res.status = 505;
        res.body = "<!DOCTYPE html>(╯□°)╯︵ ┻━┻";
    }
};

const User = struct {
    first_name: []u8,
    last_name: []u8,
    email: []u8,
};

//------------------------- Main --------------------------------------------
pub fn main() !void {

    // - Allocation -
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    // - Postgres -
    var pool = try pg.Pool.init(allocator, .{ .size = 10, .connect = .{ .port = 5432, .host = "127.0.0.1" }, .auth = .{
        .username = "thomasfsr91",
        .database = "training_db",
        .password = "feliz1989",
        .timeout = 10_000,
    } });

    defer pool.deinit();

    // - Handler -
    var app = App{ .pool = pool };

    // - server -
    const PORT = 3000;
    var server = try httpz.Server(*App).init(
        allocator,
        .{
            .port = PORT,
            .request = .{ .max_form_count = 20 },
        },
        &app,
    );

    defer server.deinit();
    defer server.stop();
    var router = try server.router(.{});

    // - css -
    router.get("/tailwindcss", serve_tailwind, .{});

    // - html -
    router.get("/", index, .{});
    router.get("/login", login, .{});
    router.get("/register", register, .{});
    router.put("/writing_user", writing_user, .{});
    router.put("/dashboard", dashboard, .{});
    // router.get("/workout_table", workout_table, .{});
    router.put("/submit_workout", submit_workout, .{});
    router.get("/cell_workout", cell_workout, .{});

    router.get("/error", @"error", .{});

    // - run -
    std.debug.print("listening http://localhost:{d}/\n", .{PORT});
    try server.listen();
}

//-------------------------- Utilities -------------------------------------
const BcryptResult = struct {
    hash: [23]u8, // 23 bytes
    salt: [16]u8,
};

fn load_html(filename: []u8) []u8 {
    var buffer: [100]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fba.allocator();
    const path: []u8 = std.fmt.allocPrint(allocator, "static/{s}.html", .{filename});
    return @embedFile(path);
}

fn bcrypt_encoder(pwd: []const u8, alloc: std.mem.Allocator) ![]const u8 {
    const buf = try alloc.alloc(u8, 60);
    const options = std.crypto.pwhash.bcrypt.HashOptions{ .params = std.crypto.pwhash.bcrypt.Params.owasp, .encoding = std.crypto.pwhash.Encoding.crypt };

    const hashed = try std.crypto.pwhash.bcrypt.strHash(pwd, options, buf);
    return hashed;
}

fn bcrypt_verify(str: []const u8, pwd: []const u8) bool {
    const options: std.crypto.pwhash.bcrypt.VerifyOptions = .{ .silently_truncate_password = false };
    std.crypto.pwhash.bcrypt.strVerify(str, pwd, options) catch {
        return false;
    };
    return true;
}

fn generateUUIDv4(allocator: std.mem.Allocator) ![]const u8 {
    // 1. Generate random bytes
    var bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&bytes);

    // 2. Set version 4 (0100) and variant (10) bits
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;

    // 3. Format as UUID string
    const result = try std.fmt.allocPrint(allocator, "{s}-{s}-{s}-{s}-{s}", .{
        std.fmt.fmtSliceHexLower(bytes[0..4]), // First segment (8 chars)
        std.fmt.fmtSliceHexLower(bytes[4..6]), // Second segment (4 chars)
        std.fmt.fmtSliceHexLower(bytes[6..8]), // Third segment (4 chars)
        std.fmt.fmtSliceHexLower(bytes[8..10]), // Fourth segment (4 chars)
        std.fmt.fmtSliceHexLower(bytes[10..16]), // Fifth segment (12 chars)
    });
    return result;
}

fn decodeUUIDv4(allocator: std.mem.Allocator, str: []u8) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{s}-{s}-{s}-{s}-{s}", .{ std.fmt.fmtSliceHexLower(str[0..4]), std.fmt.fmtSliceHexLower(str[4..6]), std.fmt.fmtSliceHexLower(str[6..8]), std.fmt.fmtSliceHexLower(str[8..10]), std.fmt.fmtSliceHexLower(str[10..16]) });
}

fn printUnixMicroTimestamp(unix_micro: i64, alloc: std.mem.Allocator) ![]u8 {
    const seconds = @divFloor(unix_micro, 1_000_000);
    const tm_ptr = c.gmtime(&seconds);
    var buffer = try alloc.alloc(u8, 11);
    _ = c.strftime(&buffer[0], buffer.len, "%Y-%m-%d", tm_ptr);
    return buffer;
}
//------------------------- Functions --------------------------------------

fn @"error"(_: *App, _: *httpz.Request, _: *httpz.Response) !void {
    return error.ActionError;
}

fn serve_tailwind(_: *App, _: *httpz.Request, res: *httpz.Response) !void {
    const file_path = "./src/css/out.css";
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();

    const contents = try file.readToEndAlloc(res.arena, std.math.maxInt(usize));
    res.content_type = .CSS;
    res.body = contents;
}

fn index(_: *App, _: *httpz.Request, res: *httpz.Response) !void {
    const html_index = load_html("index");
    res.status = 200;
    res.content_type = .HTML;
    res.body = html_index;
}

fn login(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const html_index = load_html("login");

    const session_token = req.cookies().get("session_token") orelse "";

    if (session_token.len > 0) {
        print("session_token: {s}\n", .{session_token});
        var row = try app.pool.row("SELECT created_at FROM session_state WHERE id = $1", .{session_token}) orelse {
            res.status = 200;
            res.content_type = .HTML;
            res.body = html_index;
            return;
        };
        defer row.deinit() catch {};
        const created_at = row.get(i64, 0);
        print("created_at: {any}\n", .{created_at});
        const current_time = std.time.microTimestamp();
        const count_microseconds = current_time - created_at;
        // const microseconds_per_day = 86_400_000_000; 
        const microseconds_per_seconds = 1_000_000; 
        const days_diff = @divFloor(count_microseconds, microseconds_per_seconds);
        print("count: {d}\n", .{days_diff});
        res.status = 200;
        res.content_type = .HTML;
        res.body = html_index;
        return;
    } else {
        res.status = 200;
        res.content_type = .HTML;
        res.body = html_index;
        return;
    }
}

fn dashboard(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const is_hx = req.headers.get("hx-request") orelse "false";
    if (std.mem.eql(u8, is_hx, "true") == false) {
        res.status = 404;
        res.body = "NOPE!";
        return;
    }

    var it = (try req.formData()).iterator();

    const html_dashboard = load_html("dashboard");

    var input_email: []const u8 = "";
    var input_password: []const u8 = "";

    while (it.next()) |kv| {
        if (std.mem.eql(u8, kv.key, "email")) {
            input_email = kv.value;
        }
        if (std.mem.eql(u8, kv.key, "password")) {
            input_password = kv.value;
        }
    }

    if (input_email.len == 0 or input_password.len == 0) {
        res.status = 200;
        res.content_type = .HTML;
        res.body = "Missing email or password";
        return;
    }
    if (input_email.len > 0 and input_password.len > 0) {
        var row = try app.pool.row("SELECT id, email, hashed_pwd, first_name, last_name FROM users WHERE email = $1", .{input_email}) orelse {
            const login_html = load_html("login");
            const login_with_error_html = try std.mem.replaceOwned(u8, res.arena, login_html, "hidden", "");
            res.status = 200;
            res.content_type = .HTML;
            res.body = login_with_error_html;
            return;
        };

        defer row.deinit() catch {};

        const bytes_user_id = row.get([]u8, 0);
        const user_id = try decodeUUIDv4(res.arena, bytes_user_id);
        const user_email = row.get([]u8, 1);
        const user_hashed_pwd = row.get([]u8, 2);
        const user_first_name = row.get([]u8, 3);
        const user_last_name = row.get([]u8, 4);

        const valid_password = bcrypt_verify(user_hashed_pwd, input_password);

        if (valid_password) {
            const template = try std.mem.replaceOwned(u8, res.arena, html_dashboard, "{s}", "User {fn} {ln} has the email {em}");
            const first_name_replaced = try std.mem.replaceOwned(u8, res.arena, template, "{fn}", user_first_name);
            const last_name_replaced = try std.mem.replaceOwned(u8, res.arena, first_name_replaced, "{ln}", user_last_name);
            const email_replaced = try std.mem.replaceOwned(u8, res.arena, last_name_replaced, "{em}", user_email);

            const session_token = try generateUUIDv4(res.arena);
            _ = try app.pool.exec("INSERT INTO session_state VALUES ($1::uuid, $2::uuid)", .{ session_token, user_id});

            const cookie_options = httpz.response.CookieOpts{
                .path = "/",
                .domain = "",
                .max_age = 600,
                .secure = false, // in production set to true (https only)
                .http_only = true,
                .partitioned = false,
                .same_site = .lax,
            };
            try res.setCookie("session_token", session_token, cookie_options);
            try res.setCookie("user_id", user_id, cookie_options);
            res.body = email_replaced;
            res.status = 200;
            res.content_type = .HTML;
            return;
        }
        if (valid_password == false) {
            const login_html = load_html("login");
            const login_with_error_html = try std.mem.replaceOwned(u8, res.arena, login_html, "hidden", "");
            res.status = 200;
            res.content_type = .HTML;
            res.body = login_with_error_html;
            return;
        }
    }
}

fn register(_: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const is_hx = req.headers.get("hx-request") orelse "false";
    if (std.mem.eql(u8, is_hx, "true") == false) {
        res.status = 404;
        res.body = "NOPE!";
        return;
    }

    const register_html = load_html("register");
    res.status = 200;
    res.content_type = .HTML;
    res.body = register_html;
}

fn writing_user(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const is_hx = req.headers.get("hx-request") orelse "false";
    if (std.mem.eql(u8, is_hx, "true") == false) {
        res.status = 404;
        res.body = "NOPE!";
        return;
    }

    var it = (try req.formData()).iterator();

    var input_email: []const u8 = "";
    var input_password: []const u8 = "";
    var input_first_name: []const u8 = "";
    var input_last_name: []const u8 = "";

    while (it.next()) |kv| {
        if (std.mem.eql(u8, kv.key, "email")) {
            input_email = kv.value;
        }
        if (std.mem.eql(u8, kv.key, "password")) {
            input_password = kv.value;
        }
        if (std.mem.eql(u8, kv.key, "first_name")) {
            input_first_name = kv.value;
        }
        if (std.mem.eql(u8, kv.key, "last_name")) {
            input_last_name = kv.value;
        }
    }

    if (input_email.len > 0 and input_password.len > 0) {
        const uuid = try generateUUIDv4(res.arena);
        const role = "user";
        const hashed_pwd = try bcrypt_encoder(input_password, res.arena);

        _ = app.pool.exec("INSERT INTO users (id, first_name, last_name, email, user_role, hashed_pwd) VALUES ($1::uuid, $2, $3, $4, $5, $6);", .{ uuid, input_first_name, input_last_name, input_email, role, hashed_pwd }) catch |err| {
            std.debug.print("Database error: {}\n", .{err});
            res.status = 200;
            const hash_debug = try std.mem.replaceOwned(u8, res.arena, "hashed {s}", "{s}", hashed_pwd);
            res.body = hash_debug;
            return;
        };

        const login_html = load_html("login");
        res.status = 200;
        res.content_type = .HTML;
        res.body = login_html;
    }
}

fn submit_workout(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const is_hx = req.headers.get("hx-request") orelse "false";
    if (std.mem.eql(u8, is_hx, "true") == false) {
        res.status = 404;
        res.body = "NOPE!";
        return;
    }

    const user_id = req.cookies().get("user_id") orelse "";

    var it = (try req.formData()).iterator();

    var exercise: []const u8 = "";
    var weight: []const u8 = "";
    var sets: []const u8 = "";
    var reps: []const u8 = "";

    while (it.next()) |kv| {
        if (std.mem.eql(u8, kv.key, "exercise")) {
            exercise = kv.value;
        }
        if (std.mem.eql(u8, kv.key, "weight")) {
            weight = kv.value;
        }
        if (std.mem.eql(u8, kv.key, "sets")) {
            sets = kv.value;
        }
        if (std.mem.eql(u8, kv.key, "reps")) {
            reps = kv.value;
        }
    }
    if (exercise.len > 0) {
        _ = app.pool.exec("INSERT INTO workout_logs (user_id, exercise, weight, sets, reps) VALUES ($1::uuid, $2, $3, $4, $5);", .{ user_id, exercise, weight, sets, reps }) catch |err| {
            std.debug.print("Database error: {}\n", .{err});
            res.status = 400;
            return;
        };
        res.status = 200;
        res.content_type = .HTML;
        res.body = "Sucessfully Registered!";
    }
}

fn cell_workout(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const user_id = req.cookies().get("user_id") orelse "";
    const wo_data = try app.pool.query("SELECT exercise, weight, sets, reps, created_at FROM workout_logs WHERE user_id = $1::uuid;", .{user_id});
    defer wo_data.deinit();

    var html = std.ArrayList(u8).init(res.arena);
    const writer = html.writer();

    while (try wo_data.next()) |row| {
        const exercise: []u8 = row.get([]u8, 0);
        const weight: i32 = row.get(i32, 1);
        const sets: i32 = row.get(i32, 2);
        const reps: i32 = row.get(i32, 3);
        const created_at: i64 = row.get(i64, 4);
        const created_at_str = try printUnixMicroTimestamp(created_at, res.arena);
        try writer.print(
            \\<tr class=ts_style>
            \\  <td class=td_style>
            \\  {s}
            \\  </td>
            \\  <td class=td_style>
            \\  {d}
            \\  </td>
            \\  <td class=td_style>
            \\  {d}
            \\  </td>
            \\  <td class=td_style>
            \\  {d}
            \\  </td>
            \\  <td class=td_style>
            \\  {s}
            \\  </td>
            \\  <td class=td_style>
            \\      <input type="checkbox" name="delete_it" value="Delete" class="scale-150">
            \\  </td>
            \\</tr>
        , .{ exercise, weight, sets, reps, created_at_str });
    }
    res.body = html.items;
    res.content_type = .HTML;
    res.status = 200;
    return;
}
