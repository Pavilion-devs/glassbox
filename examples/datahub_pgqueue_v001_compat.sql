-- DataHub pgQueue V001 greenfield schema, resolved for queue.metadata_queue_*.
-- Upstream source (Apache-2.0), pinned at commit 93336230f49c27eed0c07d3d2d4350781a256ba5:
-- metadata-io/src/main/resources/sqlsetup/pgqueue/migrations/V001__schema.sql
--
-- The final DEFAULT partition is proof-only plumbing for stock PostgreSQL 16. DataHub's
-- production SqlSetup creates time partitions through pg_partman; it does not change the
-- logical topic, lease, acknowledgement, or contiguous-offset contracts exercised here.

CREATE SCHEMA IF NOT EXISTS queue;
SET search_path TO queue, public;

CREATE TABLE IF NOT EXISTS metadata_queue_content_type (
    id smallint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    mime text NOT NULL UNIQUE
);

INSERT INTO metadata_queue_content_type (mime)
SELECT 'application/avro'
WHERE NOT EXISTS (
    SELECT 1 FROM metadata_queue_content_type WHERE mime = 'application/avro'
);

CREATE TABLE IF NOT EXISTS metadata_queue_topic (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    topic_name text NOT NULL UNIQUE,
    partition_count int NOT NULL CHECK (partition_count >= 1 AND partition_count <= 4096),
    retention_max_age_seconds int NOT NULL CHECK (retention_max_age_seconds >= 0),
    max_rows_per_topic bigint NOT NULL CHECK (max_rows_per_topic >= 0),
    max_total_payload_bytes bigint NOT NULL CHECK (max_total_payload_bytes >= 0),
    default_content_type_id smallint REFERENCES metadata_queue_content_type (id),
    aggressive_retention boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS metadata_queue_consumer_offset (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    consumer_group text NOT NULL,
    topic_id bigint NOT NULL REFERENCES metadata_queue_topic (id) ON DELETE CASCADE,
    partition_id int NOT NULL CHECK (partition_id >= 0),
    offset_value bigint NOT NULL DEFAULT 0,
    epoch bigint NOT NULL DEFAULT 0,
    UNIQUE (consumer_group, topic_id, partition_id)
);

CREATE TABLE IF NOT EXISTS metadata_queue_message (
    id bigint GENERATED ALWAYS AS IDENTITY,
    topic_id bigint NOT NULL REFERENCES metadata_queue_topic (id) ON DELETE CASCADE,
    partition_id int NOT NULL,
    routing_key text NOT NULL,
    enqueue_seq bigint NOT NULL,
    priority smallint NOT NULL DEFAULT 5,
    payload bytea NOT NULL,
    content_type_id smallint REFERENCES metadata_queue_content_type (id),
    payload_compression smallint NOT NULL DEFAULT 0 CHECK (payload_compression >= 0),
    headers jsonb,
    payload_bytes bigint GENERATED ALWAYS AS (octet_length(payload)) STORED,
    enqueued_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (id, enqueued_at),
    UNIQUE (topic_id, partition_id, enqueue_seq, enqueued_at),
    CONSTRAINT metadata_queue_message_priority_range CHECK (priority BETWEEN 0 AND 9)
) PARTITION BY RANGE (enqueued_at);

CREATE INDEX IF NOT EXISTS idx_metadata_queue_message_dequeue
    ON metadata_queue_message (topic_id, partition_id, priority, enqueue_seq);

CREATE INDEX IF NOT EXISTS idx_metadata_queue_message_enqueued_brin
    ON metadata_queue_message USING brin (enqueued_at);

CREATE TABLE IF NOT EXISTS metadata_queue_message_group_lease (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    message_id bigint NOT NULL,
    message_enqueued_at timestamptz NOT NULL,
    consumer_group text NOT NULL,
    lock_owner text NOT NULL,
    locked_until timestamptz NOT NULL,
    CONSTRAINT metadata_queue_message_group_lease_unique_msg_group UNIQUE (
        message_id,
        message_enqueued_at,
        consumer_group
    ),
    CONSTRAINT metadata_queue_message_group_lease_msg_fk
        FOREIGN KEY (message_id, message_enqueued_at)
        REFERENCES metadata_queue_message (id, enqueued_at)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_metadata_queue_message_group_lease_group_unlocked
    ON metadata_queue_message_group_lease (consumer_group, locked_until);

CREATE TABLE IF NOT EXISTS metadata_queue_consumer_registration (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    consumer_group text NOT NULL,
    topic_id bigint NOT NULL REFERENCES metadata_queue_topic (id) ON DELETE CASCADE,
    registered_at timestamptz NOT NULL DEFAULT now(),
    last_heartbeat_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (consumer_group, topic_id)
);

CREATE TABLE IF NOT EXISTS metadata_queue_message_proof_default
    PARTITION OF metadata_queue_message DEFAULT;
