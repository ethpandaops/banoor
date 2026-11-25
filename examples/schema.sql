-- State tables banoor needs, and an example signal table. On a cluster, use
-- Replicated*MergeTree engines with Distributed tables in front, and set
-- source.insertSettings.distributed_foreground_insert to 1 so a recorded
-- decision is stored before the list that includes it is published.

CREATE DATABASE IF NOT EXISTS banoor;

-- Every ban the scorer issues, every manual entry it first sees and every
-- source the allowlist newly suppresses. banoor rebuilds its state from here
-- when it starts, so manual entries, which may last longer, are kept.
CREATE TABLE IF NOT EXISTS banoor.decisions
(
    Time       DateTime64(3),
    Generation UInt64,
    Action     LowCardinality(String),
    Cidr       String,
    Points     Float64,
    Feeders    Array(String),
    Signals    Map(LowCardinality(String), Float64),
    BanNumber  UInt8,
    Expires    DateTime,
    Mode       LowCardinality(String),
    Reason     String
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(Time)
ORDER BY (Time, Cidr)
TTL toDateTime(Time) + INTERVAL 365 DAY DELETE WHERE Action NOT IN ('manual_ban', 'manual_lift');

-- One row per published generation. banoor restores from the newest; past
-- the TTL, a list that has not changed since is restored as unpublished, so
-- its entries count as additions for one generation.
CREATE TABLE IF NOT EXISTS banoor.publishes
(
    Time               DateTime64(3),
    Generation         UInt64,
    PreviousGeneration UInt64,
    Mode               LowCardinality(String),
    Entries            UInt32,
    Added              UInt32,
    Removed            UInt32,
    Deferred           UInt32,
    PayloadSha256      String,
    -- The published prefixes, so a restart counts additions against what
    -- consumers hold.
    Cidrs              Array(String)
)
ENGINE = MergeTree
ORDER BY Time
TTL toDateTime(Time) + INTERVAL 90 DAY DELETE;

-- Where consumers fetched the list from (allow.fetchers), so a restart
-- keeps them allowlisted.
CREATE TABLE IF NOT EXISTS banoor.fetchers
(
    Time    DateTime,
    User    LowCardinality(String),
    Address String
)
ENGINE = MergeTree
ORDER BY (User, Address, Time)
TTL Time + INTERVAL 35 DAY DELETE;

-- The kill switch: banoor follows the newest row.
--   INSERT INTO banoor.control (Mode, Reason) VALUES ('empty', 'why')
CREATE TABLE IF NOT EXISTS banoor.control
(
    Time   DateTime64(3) DEFAULT now64(3),
    Mode   Enum8('enforce' = 1, 'shadow' = 2, 'empty' = 3),
    Reason String,
    Author LowCardinality(String) DEFAULT currentUser()
)
ENGINE = MergeTree
ORDER BY Time;

-- An example signal source: refused SSH attempts per minute, source and
-- reporting host, filled by whatever ships the logs (pkg/sshlog has the
-- patterns that extract them from raw sshd lines).
CREATE TABLE IF NOT EXISTS banoor.ssh_failures
(
    Minute   DateTime,
    Feeder   LowCardinality(String),
    Kind     LowCardinality(String),
    Address  String,
    Attempts UInt64
)
ENGINE = SummingMergeTree(Attempts)
PARTITION BY toDate(Minute)
ORDER BY (Minute, Feeder, Kind, Address)
TTL Minute + INTERVAL 30 DAY DELETE;
