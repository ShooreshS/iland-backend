\set ON_ERROR_STOP on
\copy (SELECT current_setting('server_version') AS postgres_version, current_setting('block_size')::integer AS page_size_bytes, now() AT TIME ZONE 'utc' AS measured_at_utc) TO STDOUT WITH CSV HEADER

VACUUM (ANALYZE) poll_zk_votes;

\copy (
  SELECT
    count(*) AS row_count,
    avg(pg_column_size(row_value))::numeric(20,2) AS mean_row_bytes,
    min(pg_column_size(row_value)) AS min_row_bytes,
    max(pg_column_size(row_value)) AS max_row_bytes
  FROM poll_zk_votes AS row_value
) TO STDOUT WITH CSV HEADER

\copy (
  SELECT
    c.relname AS relation_name,
    pg_relation_size(c.oid) AS heap_bytes,
    pg_indexes_size(c.oid) AS index_bytes,
    pg_total_relation_size(c.oid) - pg_relation_size(c.oid) - pg_indexes_size(c.oid) AS toast_bytes,
    pg_total_relation_size(c.oid) AS total_bytes,
    c.reloptions AS relation_options
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = current_schema()
    AND c.relname = 'poll_zk_votes'
) TO STDOUT WITH CSV HEADER

\copy (
  SELECT
    indexname,
    indexdef
  FROM pg_indexes
  WHERE schemaname = current_schema()
    AND tablename = 'poll_zk_votes'
  ORDER BY indexname
) TO STDOUT WITH CSV HEADER
