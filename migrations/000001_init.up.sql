CREATE TABLE users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('employee', 'moderator')),
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE pvz (
    id UUID PRIMARY KEY,
    registration_date TIMESTAMP NOT NULL,
    city TEXT NOT NULL CHECK (city IN ('Москва', 'Санкт-Петербург', 'Казань'))
);

CREATE TABLE receptions (
    id UUID PRIMARY KEY,
    date_time TIMESTAMP NOT NULL,
    pvz_id UUID NOT NULL REFERENCES pvz(id),
    status TEXT NOT NULL CHECK (status IN ('in_progress', 'close'))
);

CREATE TABLE products (
    id UUID PRIMARY KEY,
    date_time TIMESTAMP NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('электроника', 'одежда', 'обувь')),
    reception_id UUID NOT NULL REFERENCES receptions(id)
);

-- Indexes for better performance
CREATE INDEX idx_receptions_pvz_id ON receptions(pvz_id);
CREATE INDEX idx_receptions_status ON receptions(status);
CREATE INDEX idx_products_reception_id ON products(reception_id);