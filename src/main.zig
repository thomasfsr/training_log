const pg = @import("pg");
const std = @import("std");
const httpz = @import("httpz");

//------------------------- BaseModels --------------------------------------

const App = struct {
    pool: *pg.Pool,
    pub fn notFound(_: *App, _: *httpz.Request, res: *httpz.Response) !void {
        res.status = 404;
        res.body = "NOPE!";
    }
    pub fn uncaughtError(_: *App, req: *httpz.Request, res: *httpz.Response, err: anyerror) void {
    std.debug.print("uncaught http error at {s}: {}\n", .{ req.url.path, err });

    // Alternative to res.content_type = .TYPE
    // useful for dynamic content types, or content types not defined in
    // httpz.ContentType
    res.headers.add("content-type", "text/html; charset=utf-8");

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
    router.get("/", index, .{});
    router.get("/login", login, .{});
    router.put("/auth", auth, .{});
    // router.get("/user/:id", getUser, .{});
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

// fn bcrypt_encoder(pwd: []const u8) ![]const u8 {
//     const params = std.crypto.pwhash.bcrypt.Params.owasp;
//     const salt_length = 16;
//     var salt: [salt_length]u8 = undefined;
//     std.crypto.random.bytes(&salt);
//     const hashed_pwd = std.crypto.pwhash.bcrypt.bcrypt(pwd, salt, params);
//     return &hashed_pwd;
// }


fn bcrypt_encoder(pwd: []const u8) !BcryptResult {
    const params = std.crypto.pwhash.bcrypt.Params.owasp;
    var salt: [16]u8 = undefined;
    std.crypto.random.bytes(&salt);
    const hash = std.crypto.pwhash.bcrypt.bcrypt(pwd, salt, params);
    return BcryptResult{
        .hash = hash,
        .salt = salt,
    };
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

fn auth(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    var it = (try req.formData()).iterator();

    const html_auth = @embedFile("static/auth.html");

    var email: []const u8 = "";
    var password: []const u8 = "";
    var hashed_pwd = "";

    while (it.next()) |kv| {
        if (std.mem.eql(u8, kv.key, "email")) {
            email = kv.value;
        }
        if (std.mem.eql(u8, kv.key, "password")) {
            password = kv.value;
        }
    }

    if (email.len == 0 or password.len == 0) {
        res.status = 200;
        res.content_type = .HTML;
        res.body = "Missing email or password";
        return;
    }
    if (email.len > 0 and password.len > 0) {
        const row = try app.pool.row("select first_name, last_name, email from users where email = $1", .{email});
        hashed_pwd = try bcrypt_encoder(password).hash;

    if (row) |r| {
        const user_first_name = r.get([]u8, 0);
        const user_last_name = r.get([]u8, 1);
        const user_email = r.get([]u8, 2);

        const template = try std.mem.replaceOwned(u8, res.arena, html_auth,"{s}", "User {fn} {ln} has the email {em}");
        const first_name_replaced = try std.mem.replaceOwned(u8, res.arena, template,"{fn}", user_first_name);
        const last_name_replaced = try std.mem.replaceOwned(u8, res.arena, first_name_replaced,"{ln}", user_last_name);
        const email_replaced = try std.mem.replaceOwned(u8, res.arena, last_name_replaced,"{em}", user_email);

        res.body = email_replaced;
        res.status = 200;
        res.content_type = .HTML;
        return;
        }
    if (row == null) {
        const template = try std.mem.replaceOwned(u8, res.arena, html_auth,"{s}", "User not found. {em} {hpwd}");
        const email_replaced = try std.mem.replaceOwned(u8, res.arena, template,"{em}", email);
        const hashed_pwd_replaced = try std.mem.replaceOwned(u8, res.arena, email_replaced,"{hpwd}", hashed_pwd);
        res.body = hashed_pwd_replaced;
        res.status = 200;
        res.content_type = .HTML;
        }
    }
}


// fn getUser(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
//     const user_id = req.param("id").?;

//     const row = try app.pool.row("select first_name, last_name from users where id = $1", .{user_id});
    

//     if (row) |r| {
//         try res.json(.{
//             .first_name = r.get([]u8, 0), 
//             .last_name = r.get([]u8, 1) 
//             }, .{});
//     } 
//     else {
//         res.status = 404;
//         res.body = "User not found";
//     }
// }
