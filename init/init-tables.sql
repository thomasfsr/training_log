CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    user_role VARCHAR(20) NOT NULL,
    hashed_pwd BYTEA NOT NULL,
    salt BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS exercise_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    exercise VARCHAR(50) NOT NULL,
    weight DECIMAL(10,2),
    sets INTEGER,
    reps INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (first_name, last_name, email) VALUES
('Alice', 'Martins', 'alice.martins@example.com', ),
('Bruno', 'Silva', 'bruno.silva@example.com'),
('Carla', 'Souza', 'carla.souza@example.com'),
('Diego', 'Pereira', 'diego.pereira@example.com'),
('Elisa', 'Fernandes', 'elisa.fernandes@example.com');

INSERT INTO exercise_logs (user_id, exercise, weight, sets, reps) VALUES
(1, 'Squat', 80.00, 4, 10),
(2, 'Bench Press', 60.00, 3, 8),
(3, 'Deadlift', 100.00, 5, 5),
(4, 'Overhead Press', 35.00, 3, 10),
(5, 'Pull-ups', NULL, 4, 12);
