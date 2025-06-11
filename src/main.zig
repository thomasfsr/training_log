const pg = @import("pg");
const std = @import("std");
const httpz = @import("httpz");
const print = std.debug.print;

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
    res.body = "<!DOCTYPE html>(╯°□°)╯︵ ┻━┻";}
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
    var pool = try pg.Pool.init(
        allocator, .{
            .size = 10,
            .connect = .{
                .port = 5432,
                .host = "127.0.0.1"},
            
            .auth = .{
                .username = "thomasfsr91", 
                .database = "training_db", 
                .password = "feliz1989",
                .timeout = 10_000,
            } });
    
    defer pool.deinit();

// - Handler - 
    var app = App{.pool = pool};

// - server -
    const PORT = 3000;
    var server = try httpz.Server(*App).init(
        allocator,
        .{
            .port = PORT,
            .request = .{.max_form_count = 20},
        },&app,
        );
    
    defer server.deinit();
    defer server.stop();
    var router = try server.router(.{});

// - css - 
    router.get("/tailwindcss", serve_tailwind, .{});

// - html -
    router.get("/", login, .{});
    router.get("/register", register, .{});
    router.put("/writing_user", writing_user, .{});
    router.put("/dashboard", dashboard, .{});
    router.get("/workout_table", workout_table, .{});
    router.put("/submit_workout", submit_workout, .{});

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

fn bcrypt_encoder(pwd: []const u8, alloc: std.mem.Allocator) ![]const u8 {
    const buf = try alloc.alloc(u8, 60);
    const options = std.crypto.pwhash.bcrypt.HashOptions{
        .params = std.crypto.pwhash.bcrypt.Params.owasp,
        .encoding = std.crypto.pwhash.Encoding.crypt};

    const hashed = try std.crypto.pwhash.bcrypt.strHash(pwd, options, buf);
    return hashed;
}

fn bcrypt_verify(str: []const u8, pwd: []const u8) bool {
    const options: std.crypto.pwhash.bcrypt.VerifyOptions = .{.silently_truncate_password=false};
    std.crypto.pwhash.bcrypt.strVerify(str, pwd, options) catch {return false;};
    return true;
}

pub fn generateUUIDv4(allocator: std.mem.Allocator) ![]const u8 {
    // 1. Generate random bytes
    var bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&bytes);

    // 2. Set version 4 (0100) and variant (10) bits
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;

    // 3. Format as UUID string
    const result = try std.fmt.allocPrint(allocator, 
        "{s}-{s}-{s}-{s}-{s}", .{
            std.fmt.fmtSliceHexLower(bytes[0..4]),   // First segment (8 chars)
            std.fmt.fmtSliceHexLower(bytes[4..6]),   // Second segment (4 chars)
            std.fmt.fmtSliceHexLower(bytes[6..8]),   // Third segment (4 chars)
            std.fmt.fmtSliceHexLower(bytes[8..10]),  // Fourth segment (4 chars)
            std.fmt.fmtSliceHexLower(bytes[10..16]), // Fifth segment (12 chars)
        }
    );
    print("{s}", .{result});
    return result;
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
    const html_index = @embedFile("static/index.html");
    res.status = 200;
    res.content_type = .HTML;
    res.body = html_index;
}

fn login(_: *App, _: *httpz.Request, res: *httpz.Response) !void {
    const html_index = @embedFile("static/login.html");
    res.status = 200;
    res.content_type = .HTML;
    res.body = html_index;
}



fn dashboard(app: *App, req: *httpz.Request, res: *httpz.Response) !void {

    const is_hx = req.headers.get("hx-request") orelse "false";
    if (std.mem.eql(u8, is_hx, "true")==false){
        res.status = 404;
        res.body = "NOPE!";
        return;}

    var it = (try req.formData()).iterator();

    const html_auth = @embedFile("static/dashboard.html");

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
        const row = try app.pool.row("select id, email, hashed_pwd, first_name, last_name from users where email = $1", .{input_email});
        // hashed_pwd = try bcrypt_encoder(password);

    if (row) |r| {
        const user_id = r.get([]u8, 0);
        const user_email = r.get([]u8, 1);
        const user_hashed_pwd = r.get([]u8, 2);
        const user_first_name = r.get([]u8, 3);
        const user_last_name = r.get([]u8, 4);

        const valid_password = bcrypt_verify(user_hashed_pwd, input_password);

        if (valid_password) {
            const template = try std.mem.replaceOwned(u8, res.arena, html_auth,"{s}", "User {fn} {ln} has the email {em}");
            const first_name_replaced = try std.mem.replaceOwned(u8, res.arena, template,"{fn}", user_first_name);
            const last_name_replaced = try std.mem.replaceOwned(u8, res.arena, first_name_replaced,"{ln}", user_last_name);
            const email_replaced = try std.mem.replaceOwned(u8, res.arena, last_name_replaced,"{em}", user_email);

            const session_token = try generateUUIDv4(res.arena);

            _ = try app.pool.exec("INSERT INTO session_state VALUES ($1, $2)", .{session_token, user_id});

            const cookie_options = httpz.response.CookieOpts{
                .path = "/",
                .domain = "",
                .max_age = 600,
                .secure = false, // in production set to true (https only)
                .http_only = true,
                .partitioned= false,
                .same_site = .lax,
                };
            print("{s}\n\n", .{user_id});
            print("{x}\n\n", .{user_id});
            const user_id_str = try std.fmt.allocPrint(res.arena,
                                                        "{s}-{s}-{s}-{s}-{s}",.{
                                                            std.fmt.fmtSliceHexLower(user_id[0..4]),
                                                            std.fmt.fmtSliceHexLower(user_id[4..6]),
                                                            std.fmt.fmtSliceHexLower(user_id[6..8]),
                                                            std.fmt.fmtSliceHexLower(user_id[8..10]),
                                                            std.fmt.fmtSliceHexLower(user_id[10..16]),});
            print("{s}\n\n", .{user_id_str});
            try res.setCookie("session_token", session_token, cookie_options);
            try res.setCookie("user_id", user_id_str, cookie_options);
            res.body = email_replaced;
            res.status = 200;
            res.content_type = .HTML;
            return;
            }
        if (valid_password == false) {
            const html_index = @embedFile("static/login.html");
            const html_index2 = try std.mem.replaceOwned(u8, res.arena, html_index,"hidden", "");
            res.status = 200;
            res.content_type = .HTML;
            res.body = html_index2;
            return;

            // const template = try std.mem.replaceOwned(u8, res.arena, html_auth,"{s}", "Password wrong!");
            // res.body = template;
            // res.status = 200;
            // res.content_type = .HTML;
            // return;
        }
    }

    if (row == null) {
        const html_index = @embedFile("static/login.html");

        res.status = 200;
        res.content_type = .HTML;
        res.body = html_index;
        }
    }
}

fn register(_: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const is_hx = req.headers.get("hx-request") orelse "false";
    if (std.mem.eql(u8, is_hx, "true")==false){
        res.status = 404;
        res.body = "NOPE!";
        return;}

    const html_register = @embedFile("static/register.html");
    res.status = 200;
    res.content_type = .HTML;
    res.body = html_register;
}

fn writing_user(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const is_hx = req.headers.get("hx-request") orelse "false";
    if (std.mem.eql(u8, is_hx, "true")==false){
        res.status = 404;
        res.body = "NOPE!";
        return;}

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
        
        _ = app.pool.exec("INSERT INTO users (id, first_name, last_name, email, user_role, hashed_pwd) VALUES ($1::uuid, $2, $3, $4, $5, $6);", 
        .{
                uuid,
                input_first_name,
                input_last_name,
                input_email,
                role,
                hashed_pwd}) catch |err| {
                    std.debug.print("Database error: {}\n", .{err});
                    res.status = 200;
                    const hash_debug = try std.mem.replaceOwned(u8, res.arena, "hashed {s}", "{s}", hashed_pwd);
                    res.body = hash_debug;
                    return;
                };
        res.status = 200;
        res.content_type = .HTML;
        res.body = "Sucessfully Registered!";
    }

}

fn workout_table(_: *App, _: *httpz.Request, res: *httpz.Response) !void {
    const html_table = @embedFile("static/workout_table.html");
    res.status = 200;
    res.content_type = .HTML;
    res.body = html_table;
}

fn submit_workout(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const is_hx = req.headers.get("hx-request") orelse "false";
    if (std.mem.eql(u8, is_hx, "true")==false){
        res.status = 404;
        res.body = "NOPE!";
        return;}
    
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
    print("{s}", .{user_id});
    if (exercise.len > 0) {   
        _ = app.pool.exec("INSERT INTO workout_logs (user_id, exercise, weight, sets, reps) VALUES ($1, $2, $3, $4, $5);", 
        .{
                user_id,
                exercise,
                weight,
                sets,
                reps}) catch |err| {
                    std.debug.print("Database error: {}\n", .{err});
                    res.status = 400;
                    return;
                };
        res.status = 200;
        res.content_type = .HTML;
        res.body = "Sucessfully Registered!";
    }
}