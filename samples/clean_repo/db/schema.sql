CREATE TABLE users (
    id uuid primary key,
    email text not null
);
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY users_own_rows ON users TO authenticated USING (auth.uid() = id);
