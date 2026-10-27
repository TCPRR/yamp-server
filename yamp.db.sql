BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "channels" (
	"pos"	INTEGER,
	"name"	TEXT,
	"type"	INTEGER,
	"space"	INTEGER,
	"parent"	TEXT,
	"id"	TEXT,
	FOREIGN KEY("space") REFERENCES "spaces"("id") ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS "dm" (
	"starter"	TEXT,
	"recipient"	TEXT
);
CREATE TABLE IF NOT EXISTS "friendreq" (
	"sender"	TEXT,
	"recver"	TEXT
);
CREATE TABLE IF NOT EXISTS "friendship" (
	"sender"	TEXT,
	"accepter"	TEXT
);
CREATE TABLE IF NOT EXISTS "gc" (
	"name"	TEXT,
	"owner"	TEXT,
	"icon"	TEXT,
	"id"	TEXT UNIQUE,
	PRIMARY KEY("id")
);
CREATE TABLE IF NOT EXISTS "messages" (
	"channel"	VARCHAR,
	"author"	VARCHAR,
	"content"	VARCHAR,
	"timestamp"	INTEGER,
	"reply"	TEXT,
	"id"	TEXT UNIQUE,
	"type"	INTEGER
);
CREATE TABLE IF NOT EXISTS "sessions" (
	"user-id"	TEXT,
	"device-type"	INTEGER,
	"device"	TEXT,
	"token"	TEXT
);
CREATE TABLE IF NOT EXISTS "space-invites" (
	"space"	TEXT,
	"uses"	INTEGER,
	"code"	TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS "space-roles" (
	"name"	TEXT,
	"pos"	TEXT,
	"id"	INTEGER,
	PRIMARY KEY("id")
);
CREATE TABLE IF NOT EXISTS "spaces" (
	"name"	VARCHAR(255) NOT NULL,
	"display_name"	VARCHAR(255),
	"icon"	TEXT,
	"banner"	TEXT,
	"description"	TEXT,
	"type"	INTEGER,
	"id"	TEXT,
	"owner"	TEXT,
	PRIMARY KEY("id"),
	FOREIGN KEY("owner") REFERENCES "users"("id")
);
CREATE TABLE IF NOT EXISTS "user-gc" (
	"user-id"	TEXT,
	"gc-id"	TEXT
);
CREATE TABLE IF NOT EXISTS "user-space" (
	"user-id"	TEXT NOT NULL,
	"space-id"	TEXT NOT NULL,
	"usrsettings"	TEXT,
	"roles"	INTEGER,
	"pos"	INTEGER,
	FOREIGN KEY("space-id") REFERENCES "spaces"("id") ON DELETE CASCADE,
	FOREIGN KEY("user-id") REFERENCES "users"("id") ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS "users" (
	"id"	TEXT NOT NULL,
	"name"	VARCHAR(64) NOT NULL UNIQUE,
	"display_name"	VARCHAR(255),
	"password"	VARCHAR(255),
	"pfp"	VARCHAR(512),
	"description"	VARCHAR(1024),
	"email"	VARCHAR(255),
	PRIMARY KEY("id")
);
COMMIT;
