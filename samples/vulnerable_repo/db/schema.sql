CREATE TABLE users (
    id uuid primary key,
    email text not null,
    role text default 'user'
);

CREATE TABLE orders (
    id uuid primary key,
    user_id uuid references users(id)
);

CREATE POLICY anyone_select ON users FOR SELECT USING (true);
