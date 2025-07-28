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
    // -------- Root endpoint has CONTENT.
    router.get("/", index, .{});
    router.put("/auth", auth, .{});

    // -------- Endpoints that swaps the CONTENT.
    router.get("/login", login_page, .{});
    router.get("/register", register_page, .{});
    router.get("/dashboard", dashboard_page, .{});

    // -------- Endpoints of divs.
    router.put("/writing_user", writing_user, .{});
    router.put("/exercise_adding", exercise_adding, .{});

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
fn decodeCookieValue(value: []const u8) ![]const u8 {
    if (value.len == 0) return value;
    const trimmed = std.mem.trim(u8, value, "\"");
    if (std.mem.indexOf(u8, trimmed, "%") == null) return trimmed;
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

fn isSafeChar(chara: u8) bool {
    return std.ascii.isAlphanumeric(chara) or chara == '-' or chara == '_' or chara == '.' or chara == '~';
}
//------------------------- Functions --------------------------------------

fn @"error"(_: *App, _: *httpz.Request, _: *httpz.Response) !void {
    return error.ActionError;
}
// - HX-GET - tailwind -
fn serve_tailwind(_: *App, _: *httpz.Request, res: *httpz.Response) !void {
    const file_path = "./src/css/out.css";
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();

    const contents = try file.readToEndAlloc(res.arena, std.math.maxInt(usize));
    res.body = contents;
    res.content_type = .CSS;
    res.status = 200;
    return;
}

// - INDEX PAGE -
fn index(_: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const html_index = @embedFile("static/index.html");

    // - back-to-login logic -
    const query = try req.query();
    const is_back = query.get("back") != null;
    if (is_back) {
        res.header("Set-Cookie", "session_token=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/;");
        res.header("Set-Cookie", "user_id=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/;");
        res.header("Set-Cookie", "email=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/;");
        res.body = try std.mem.replaceOwned(u8, res.arena, html_index, "{{route}}", "/login");
        res.content_type = .HTML;
        res.status = 200;
        return;
    }

    // - token validation -

    const token_email = req.cookies().get("email");
    if (token_email != null) {
        res.body = try std.mem.replaceOwned(u8, res.arena, html_index, "{{route}}", "/dashboard");
        res.content_type = .HTML;
        res.status = 200;
        return;
    }

    // - default as login page -

    res.body = try std.mem.replaceOwned(u8, res.arena, html_index, "{{route}}", "/login");
    res.content_type = .HTML;
    res.status = 200;
    return;
}

// - HX-GET - LOGIN -
fn login_page(_: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const is_hx = req.headers.get("hx-request") orelse "false";
    if (std.mem.eql(u8, is_hx, "false")) {
        res.body = "NOPE!";
        res.status = 404;
        return;
    }
    const html_login = @embedFile("static/login.html");
    res.body = html_login;
    res.content_type = .HTML;
    res.status = 200;
    return;
}

// - HX-GET - REGISTER -
fn register_page(_: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const is_hx = req.headers.get("hx-request") orelse "false";
    if (std.mem.eql(u8, is_hx, "false")) {
        res.body = "NOPE!";
        res.status = 404;
        return;
    }

    const register_html = @embedFile("static/register.html");
    res.body = register_html;
    res.content_type = .HTML;
    res.status = 200;
}

// - HX-PUT - AUTH -
fn auth(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    var input_email: []const u8 = "";
    var input_password: []const u8 = "";

    var it = (try req.formData()).iterator();
    while (it.next()) |kv| {
        if (std.mem.eql(u8, kv.key, "email")) {
            input_email = kv.value;
        }
        if (std.mem.eql(u8, kv.key, "password")) {
            input_password = kv.value;
        }
    }

    var user_row = try app.pool.row("SELECT id, email, hashed_pwd, first_name, last_name FROM users WHERE email = $1", .{input_email}) orelse {
        res.body =
            \\<div class="mb-4 h-6 text-red-500" id="hidden_alert" hx-swap-oob="true"> Password or Email invalid!</div>
        ;
        res.status = 200;
        res.content_type = .HTML;
        return;
    };
    defer user_row.deinit() catch {};

    const bytes_user_id = user_row.get([]u8, 0);
    const user_id = try decodeUUIDv4(res.arena, bytes_user_id);
    const user_email = user_row.get([]u8, 1);
    const user_hashed_pwd = user_row.get([]u8, 2);

    // -- user encoding --
    const user_first_name = user_row.get([]u8, 3);
    var list = std.ArrayList(u8).init(res.arena);
    defer list.deinit();
    try std.Uri.Component.percentEncode(list.writer(), user_first_name, isSafeChar);
    const first_name_encoded = try list.toOwnedSlice();

    const user_last_name = user_row.get([]u8, 4);
    var list2 = std.ArrayList(u8).init(res.arena);
    defer list2.deinit();
    try std.Uri.Component.percentEncode(list2.writer(), user_last_name, isSafeChar);
    const last_name_encoded = try list2.toOwnedSlice();
    // -- end of user encoding --

    const valid_password = bcrypt_verify(user_hashed_pwd, input_password);

    if (valid_password == false) {
        res.body =
            \\<div class="mb-4 h-6 text-red-500" id="hidden_alert" hx-swap-oob="true"> Password or Email invalid!</div>
        ;
        res.status = 200;
        res.content_type = .HTML;
        return;
    }
    const session_token = try generateUUIDv4(res.arena);
    _ = try app.pool.exec("INSERT INTO session_state VALUES ($1::uuid, $2::uuid)", .{ session_token, user_id });

    const cookie_options = httpz.response.CookieOpts{
        .path = "/",
        .domain = "",
        .max_age = 60,
        .secure = false,
        .http_only = true,
        .partitioned = false,
        .same_site = .lax,
    };
    try res.setCookie("session_token", session_token, cookie_options);
    try res.setCookie("user_id", user_id, cookie_options);
    try res.setCookie("email", user_email, cookie_options);
    try res.setCookie("first_name", first_name_encoded, cookie_options);
    try res.setCookie("last_name", last_name_encoded, cookie_options);
    res.header("hx-refresh", "true");
    return;
}

// - HX-GET - DASHBOARD -
fn dashboard_page(app: *App, req: *httpz.Request, res: *httpz.Response) !void {

    // You should implement back the validation of the life of the token in the dash. If it expired, it should return res.body = NOPE!.
    const is_hx = req.headers.get("hx-request") orelse "false";
    if (std.mem.eql(u8, is_hx, "false")) {
        res.body = "Olá!";
        res.status = 404;
        return;
    }
    const user_id = req.cookies().get("user_id") orelse "";

    // -- decode first name --
    const user_first_name = req.cookies().get("first_name") orelse "";
    const output_buffer = try res.arena.alloc(u8, user_first_name.len);
    const user_first_name_decoded = std.Uri.percentDecodeBackwards(output_buffer, user_first_name);
    const user_first_name_upper = try std.ascii.allocUpperString(res.arena, user_first_name_decoded);
    // -- end decoded --

    // -- decode last name --
    const user_last_name = req.cookies().get("last_name") orelse "";
    const output_buffer2 = try res.arena.alloc(u8, user_last_name.len);
    const user_last_name_decoded = std.Uri.percentDecodeBackwards(output_buffer2, user_last_name);
    const user_last_name_upper = try std.ascii.allocUpperString(res.arena, user_last_name_decoded);
    // -- end decoded --

    const user_email = req.cookies().get("email") orelse "";

    const html_dashboard_load = @embedFile("static/dashboard.html");
    var html_dashboard = try std.fmt.allocPrint(res.arena, "{s}", .{html_dashboard_load});
    html_dashboard = try std.mem.replaceOwned(u8, res.arena, html_dashboard, "{{first_name}}", user_first_name_upper);
    html_dashboard = try std.mem.replaceOwned(u8, res.arena, html_dashboard, "{{last_name}}", user_last_name_upper);
    html_dashboard = try std.mem.replaceOwned(u8, res.arena, html_dashboard, "{{email}}", user_email);

    const wo_data = try app.pool.query("SELECT exercise, weight, sets, reps, created_at FROM workout_logs WHERE user_id = $1::uuid;", .{user_id});
    defer wo_data.deinit();

    var table_html = std.ArrayList(u8).init(res.arena);
    const writer = table_html.writer();

    while (true) {
        const row = try wo_data.next() orelse break;
        const exercise: []u8 = row.get([]u8, 0);
        const weight: i32 = row.get(i32, 1);
        const sets: i32 = row.get(i32, 2);
        const reps: i32 = row.get(i32, 3);
        const created_at: i64 = row.get(i64, 4);
        const created_at_str: []u8 = try printUnixMicroTimestamp(created_at, res.arena);
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

    //    const cookie_options = httpz.response.CookieOpts{
    //        .path = "/",
    //        .domain = "",
    //        .max_age = 60,
    //        .secure = false,
    //        .http_only = true,
    //        .partitioned = false,
    //        .same_site = .lax,
    //    };
    //    try res.setCookie("session_token", session_token, cookie_options);
    //    try res.setCookie("user_id", user_id, cookie_options);
    //    try res.setCookie("email", user_email, cookie_options);

    if (table_html.items.len == 0) {
        html_dashboard = try std.mem.replaceOwned(u8, res.arena, html_dashboard, "{{workout_table}}", "");
        res.body = html_dashboard;
        res.content_type = .HTML;
        res.status = 200;
        return;
    }

    const table_html_items = table_html.items;
    html_dashboard = try std.mem.replaceOwned(u8, res.arena, html_dashboard, "{{workout_table}}", table_html_items);
    res.body = html_dashboard;
    res.content_type = .HTML;
    res.status = 200;
    return;
}

// - registering user -
fn writing_user(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const is_hx = req.headers.get("hx-request") orelse "false";
    if (std.mem.eql(u8, is_hx, "true") == false) {
        res.status = 404;
        res.body = "NOPE!";
        return;
    }

    var input_email: []const u8 = "";
    var input_password: []const u8 = "";
    var input_first_name: []const u8 = "";
    var input_last_name: []const u8 = "";

    var it = (try req.formData()).iterator();
    while (it.next()) |kv| {
        const lower_value = try std.ascii.allocLowerString(res.arena, kv.value);

        if (std.mem.eql(u8, kv.key, "email")) {
            input_email = lower_value;
        }
        if (std.mem.eql(u8, kv.key, "password")) {
            input_password = lower_value;
        }
        if (std.mem.eql(u8, kv.key, "first_name")) {
            input_first_name = lower_value;
        }
        if (std.mem.eql(u8, kv.key, "last_name")) {
            input_last_name = lower_value;
        }
    }

    var existing_email = try app.pool.rowOpts("SELECT email FROM users WHERE email = $1", .{input_email}, .{ .release_conn = true });

    if (existing_email != null) {
        const register_html = @embedFile("static/register.html");
        res.body = try std.mem.replaceOwned(u8, res.arena, register_html, "hidden", "");
        res.status = 200;
        res.content_type = .HTML;
        try existing_email.?.deinit();
        return;
    }

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

    const login_html = @embedFile("static/login.html");
    res.status = 200;
    res.content_type = .HTML;
    res.body = login_html;
}

// - HX-POST - EXERCISE -
fn exercise_adding(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const is_hx = req.headers.get("hx-request") orelse "false";
    if (std.mem.eql(u8, is_hx, "false")) {
        res.body = "NOPE!";
        res.status = 404;
        return;
    }

    const user_id = req.cookies().get("user_id") orelse {
        res.status = 200;
        res.header("HX-Refresh", "true");
        return;
    };

    var it = (try req.formData()).iterator();

    var exercise: []const u8 = "";
    var weight: []const u8 = "";
    var sets: []const u8 = "";
    var reps: []const u8 = "";

    while (it.next()) |kv| {
        const lower_value = try std.ascii.allocLowerString(res.arena, kv.value);

        if (std.mem.eql(u8, kv.key, "exercise")) {
            exercise = lower_value;
        }
        if (std.mem.eql(u8, kv.key, "weight")) {
            weight = lower_value;
        }
        if (std.mem.eql(u8, kv.key, "sets")) {
            sets = lower_value;
        }
        if (std.mem.eql(u8, kv.key, "reps")) {
            reps = lower_value;
        }
        if (std.mem.eql(u8, kv.key, "date")) {
            const date = lower_value;
            print("{s}", .{date});
        }
    }
    if (exercise.len > 0) {
        _ = app.pool.exec("INSERT INTO workout_logs (user_id, exercise, weight, sets, reps) VALUES ($1::uuid, $2, $3, $4, $5);", .{
            user_id,
            exercise,
            weight,
            sets,
            reps,
        }) catch |err| {
            std.debug.print("Database error: {}\n", .{err});
            res.status = 400;
            return;
        };
        res.status = 200;
        res.content_type = .HTML;
        const body = try std.fmt.allocPrint(res.arena,
            \\<tr class=ts_style>
            \\  <td class=td_style>
            \\  {s}
            \\  </td>
            \\  <td class=td_style>
            \\  {s}
            \\  </td>
            \\  <td class=td_style>
            \\  {s}
            \\  </td>
            \\  <td class=td_style>
            \\  {s}
            \\  </td>
            \\  <td class=td_style>
            \\  2025-07-14 
            \\  </td>
            \\  <td class=td_style>
            \\      <input type="checkbox" name="delete_it" value="Delete" class="scale-150">
            \\  </td>
            \\</tr>
        , .{ exercise, weight, sets, reps });
        res.body = body;
    }
}
