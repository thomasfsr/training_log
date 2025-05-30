const pg = @import("pg");
const std = @import("std");
const httpz = @import("httpz");

//------------------------- BaseModels --------------------------------------

const App = struct {
    pool: *pg.Pool,
};

//------------------------- Main --------------------------------------------
pub fn main() !void {

// - alloc -
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

// - handler -
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
    var app = App{.pool = pool};

// - server -
    const port = 3000;
    var server = try httpz.Server(*App).init(
        allocator, 
        .{ .port = port }, 
        &app
        );
    
    defer server.deinit();
    defer server.stop();
    var router = try server.router(.{});

// - style - 
    router.get("/tailwindcss", serve_tailwind, .{});

// - html -
    router.get("/", index, .{});
    router.get("/login", login, .{});
    router.put("/auth", auth, .{});
    router.get("/user/:id", getUser, .{});

// - run - 
    std.debug.print("listening http://localhost:{d}/\n", .{port});
    try server.listen();
}

//-------------------------- Utilities -------------------------------------

fn parseForm(body: []const u8, allocator: std.mem.Allocator) !std.StringHashMap([]const u8) {
    var map = std.StringHashMap([]const u8).init(allocator);

    var pairs = std.mem.splitScalar(u8, body, '&');
    while (pairs.next()) |pair| {
        var kv = std.mem.splitScalar(u8, pair, '=');
        const key = kv.next() orelse continue;
        const val = kv.next() orelse continue;
        try map.put(key, val);
    }

    return map;
}

//------------------------- Functions --------------------------------------

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
    const allocator = std.heap.page_allocator;
    if (req.body()) |body| {
        var form = try parseForm(body, allocator);
        if (form.get("email")) |email| {
            std.debug.print("\n{s}\n",.{email});
            const row = try app.pool.row("select first_name from users where email = $1", .{email});
            if (row) |_| {
                // std.debug.print("{any}",.{r});
                res.status = 200;
                res.content_type = .HTML;
                res.body = "User Exists.";
                return;
            }
        }
    }
    res.status = 404;
    res.content_type = .HTML;
    res.body = "User not found";
    return;
}


fn getUser(app: *App, req: *httpz.Request, res: *httpz.Response) !void {
    const user_id = req.param("id").?;

    const row = try app.pool.row("select first_name, last_name from users where id = $1", .{user_id});
    

    if (row) |r| {
        try res.json(.{
            .first_name = r.get([]u8, 0), 
            .last_name = r.get([]u8, 1) 
            }, .{});
    } 
    else {
        res.status = 404;
        res.body = "User not found";
    }
}
