-- Azure SQL production schema for auth tenancy + billing enforcement
-- Apply with your migration tool (Alembic/SQL script runner) on Azure SQL.

CREATE TABLE companies (
    id NVARCHAR(64) NOT NULL PRIMARY KEY,
    name NVARCHAR(200) NOT NULL,
    status NVARCHAR(32) NOT NULL DEFAULT 'active',
    created_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);

CREATE TABLE users (
    id INT IDENTITY(1,1) NOT NULL PRIMARY KEY,
    username NVARCHAR(255) NOT NULL UNIQUE,
    password_hash NVARCHAR(255) NOT NULL,
    full_name NVARCHAR(255) NOT NULL,
    is_admin BIT NOT NULL DEFAULT 0,
    is_active BIT NOT NULL DEFAULT 1
);

CREATE TABLE company_users (
    id NVARCHAR(100) NOT NULL PRIMARY KEY,
    company_id NVARCHAR(64) NOT NULL,
    user_id INT NOT NULL,
    role NVARCHAR(32) NOT NULL DEFAULT 'cashier',
    is_active BIT NOT NULL DEFAULT 1,
    CONSTRAINT uq_company_users UNIQUE (company_id, user_id),
    CONSTRAINT fk_company_users_company FOREIGN KEY (company_id) REFERENCES companies(id),
    CONSTRAINT fk_company_users_user FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE subscriptions (
    id NVARCHAR(100) NOT NULL PRIMARY KEY,
    company_id NVARCHAR(64) NOT NULL,
    provider NVARCHAR(32) NOT NULL DEFAULT 'stripe',
    provider_customer_id NVARCHAR(128) NULL,
    provider_subscription_id NVARCHAR(128) NULL,
    status NVARCHAR(32) NOT NULL DEFAULT 'trialing',
    current_period_end DATETIME2 NULL,
    cancel_at_period_end BIT NOT NULL DEFAULT 0,
    grace_until DATETIME2 NULL,
    updated_at DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT uq_provider_subscription UNIQUE (provider, provider_subscription_id),
    CONSTRAINT fk_subscriptions_company FOREIGN KEY (company_id) REFERENCES companies(id)
);

CREATE TABLE billing_events (
    id NVARCHAR(100) NOT NULL PRIMARY KEY,
    company_id NVARCHAR(64) NULL,
    provider NVARCHAR(32) NOT NULL DEFAULT 'stripe',
    provider_event_id NVARCHAR(128) NOT NULL UNIQUE,
    event_type NVARCHAR(120) NOT NULL,
    payload_json NVARCHAR(MAX) NOT NULL,
    processed_at DATETIME2 NULL,
    success BIT NOT NULL DEFAULT 0,
    CONSTRAINT fk_billing_events_company FOREIGN KEY (company_id) REFERENCES companies(id)
);

CREATE TABLE auth_identities (
    id NVARCHAR(100) NOT NULL PRIMARY KEY,
    user_id INT NOT NULL,
    provider NVARCHAR(32) NOT NULL,
    provider_subject NVARCHAR(255) NOT NULL,
    email NVARCHAR(255) NULL,
    last_login_at DATETIME2 NULL,
    CONSTRAINT uq_auth_identity UNIQUE (provider, provider_subject),
    CONSTRAINT fk_auth_identity_user FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX ix_company_users_company ON company_users(company_id);
CREATE INDEX ix_company_users_user ON company_users(user_id);
CREATE INDEX ix_subscriptions_company ON subscriptions(company_id);
CREATE INDEX ix_billing_events_company ON billing_events(company_id);
CREATE INDEX ix_auth_identities_user ON auth_identities(user_id);
