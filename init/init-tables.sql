CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    first_name VARCHAR(50) NOT NULL,
    last_name VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    user_role VARCHAR(20) NOT NULL,
    hashed_pwd VARCHAR(100) NOT NULL
);

CREATE TABLE IF NOT EXISTS workout_logs (
    id SERIAL PRIMARY KEY,
    user_id UUID,
    exercise VARCHAR(50) NOT NULL,
    weight DECIMAL(10,2),
    sets INTEGER,
    reps INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS session_state (
    id UUID PRIMARY KEY,
    user_id UUID,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);