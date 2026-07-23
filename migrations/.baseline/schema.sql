--
-- PostgreSQL database dump
--


-- Dumped from database version 17.10 (Debian 17.10-1.pgdg12+1)
-- Dumped by pg_dump version 17.10 (Debian 17.10-1.pgdg12+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pg_trgm; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: vector; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public;


--
-- Name: audit_schema_change(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.audit_schema_change() RETURNS event_trigger
    LANGUAGE plpgsql
    AS $$
        BEGIN
            INSERT INTO schema_audit_log (
                schema_name,
                object_type,
                object_name,
                command_tag,
                client_addr,
                client_port,
                db_user,
                application_name,
                query
            ) VALUES (
                current_schema(),
                tg_tag,
                '', -- object_name not easily available in all trigger contexts without pg_stat_activity
                tg_tag,
                inet_client_addr(),
                inet_client_port(),
                current_user,
                current_setting('application_name'),
                current_query()
            );
        EXCEPTION WHEN OTHERS THEN
            -- Silent failure to not block the DDL operation
        END;
        $$;


--
-- Name: calculate_module_execution_duration(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.calculate_module_execution_duration() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.completed_at IS NOT NULL AND OLD.completed_at IS NULL THEN
        NEW.duration_ms := EXTRACT(EPOCH FROM (NEW.completed_at - NEW.started_at)) * 1000;
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: cancel_siblings_on_workflow_fail(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.cancel_siblings_on_workflow_fail() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.status = 'failed'
       AND (OLD.status IS NULL OR OLD.status <> 'failed')
    THEN
        UPDATE module_executions
        SET status        = 'cancelled',
            completed_at  = NOW(),
            error_message = 'Workflow failed — parallel sibling cancelled'
        WHERE workflow_execution_id = NEW.id
          AND status = 'running';
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: compute_execution_event_duration(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.compute_execution_event_duration() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.event_type IN ('node_completed', 'node_failed') AND NEW.node_id IS NOT NULL THEN
        SELECT (EXTRACT(EPOCH FROM (NEW.created_at - ee.created_at)) * 1000)::bigint
        INTO NEW.duration_ms
        FROM execution_events ee
        WHERE ee.execution_id = NEW.execution_id
          AND ee.node_id = NEW.node_id
          AND ee.event_type = 'node_started'
        ORDER BY ee.created_at DESC
        LIMIT 1;
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: enforce_workflow_log_limit(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enforce_workflow_log_limit() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    n BIGINT;
BEGIN
    SELECT COUNT(*) INTO n
    FROM workflow_execution_logs
    WHERE execution_id = NEW.execution_id;
    IF n >= 5000 THEN
        RAISE EXCEPTION 'workflow_execution_logs limit reached for execution % (5000 entries)', NEW.execution_id
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: increment_and_check_module_log_count(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.increment_and_check_module_log_count() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    current_count INTEGER;
BEGIN
    UPDATE module_executions
    SET log_count = log_count + 1
    WHERE id = NEW.execution_id
    RETURNING log_count INTO current_count;

    IF current_count > 1000 THEN
        RAISE EXCEPTION 'Execution % exceeded maximum log entries (1000)', NEW.execution_id
            USING HINT = 'Log entry dropped to prevent resource exhaustion',
                  ERRCODE = 'check_violation';
    END IF;

    RETURN NEW;
END;
$$;


--
-- Name: integration_state_touch_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.integration_state_touch_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;


--
-- Name: modules_touch_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.modules_touch_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


--
-- Name: prevent_audit_modification(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.prevent_audit_modification() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION
        'Audit records are immutable — % on % is not permitted. '
        'Audit tables are append-only by security policy.',
        TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END;
$$;


--
-- Name: set_default_actor_on_execution(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.set_default_actor_on_execution() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.actor_id IS NULL AND NEW.user_id IS NOT NULL THEN
        NEW.actor_id := (
            SELECT id FROM actors
            WHERE user_id = NEW.user_id AND is_default
            LIMIT 1
        );
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: set_org_id_from_personal_org(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.set_org_id_from_personal_org() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NEW.org_id IS NULL AND NEW.user_id IS NOT NULL THEN
        NEW.org_id := (
            SELECT id FROM organizations
            WHERE owner_id = NEW.user_id AND is_personal
            LIMIT 1
        );
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: sync_active_version_graph(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.sync_active_version_graph() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- For INSERT: always sync if graph_json is non-null.
    -- For UPDATE: only sync when graph_json actually changed.
    IF TG_OP = 'INSERT' OR (OLD.graph_json IS DISTINCT FROM NEW.graph_json) THEN
        UPDATE workflow_versions
           SET graph_json = NEW.graph_json::jsonb,
               updated_at = NOW()
         WHERE workflow_id = NEW.id
           AND is_active = true;
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: update_google_calendar_integrations_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_google_calendar_integrations_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


--
-- Name: update_google_calendar_watch_channels_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_google_calendar_watch_channels_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


--
-- Name: update_module_execution_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_module_execution_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


--
-- Name: update_slack_integrations_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_slack_integrations_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


--
-- Name: update_workflow_execution_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_workflow_execution_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: _sqlx_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public._sqlx_migrations (
    version bigint NOT NULL,
    description text NOT NULL,
    installed_on timestamp with time zone DEFAULT now() NOT NULL,
    success boolean NOT NULL,
    checksum bytea NOT NULL,
    execution_time bigint NOT NULL
);


--
-- Name: actor_action_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.actor_action_log (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    actor_id uuid NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    action_type text NOT NULL,
    workflow_id uuid,
    execution_id uuid,
    summary text NOT NULL,
    details jsonb,
    org_id uuid
);


--
-- Name: actor_approval_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.actor_approval_policies (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    actor_id uuid NOT NULL,
    trigger_condition text NOT NULL,
    approval_mode text DEFAULT 'block'::text NOT NULL,
    approvers text[],
    created_at timestamp with time zone DEFAULT now(),
    org_id uuid,
    CONSTRAINT agent_approval_policies_approval_mode_check CHECK ((approval_mode = ANY (ARRAY['block'::text, 'notify'::text, 'log'::text])))
);


--
-- Name: actor_budget_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.actor_budget_policies (
    actor_id uuid NOT NULL,
    max_executions_per_hour integer,
    max_executions_total bigint,
    max_fuel_per_execution bigint,
    max_fuel_per_hour bigint,
    max_outbound_requests_per_hour integer,
    max_workflow_count integer,
    max_workflows_per_minute integer DEFAULT 10 NOT NULL,
    max_compilations_per_hour integer DEFAULT 20 NOT NULL,
    on_budget_exceeded text DEFAULT 'suspend'::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    fuel_budget_daily bigint,
    fuel_alert_threshold_pct integer DEFAULT 80 NOT NULL,
    org_id uuid,
    CONSTRAINT agent_budget_policies_on_budget_exceeded_check CHECK ((on_budget_exceeded = ANY (ARRAY['suspend'::text, 'alert'::text, 'block'::text])))
);


--
-- Name: actor_memory; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.actor_memory (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    actor_id uuid NOT NULL,
    key text NOT NULL,
    memory_type text DEFAULT 'working'::text NOT NULL,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    embedding public.vector(1024),
    metadata jsonb,
    value_enc bytea NOT NULL,
    value_key_id uuid NOT NULL,
    value_format smallint DEFAULT 0 NOT NULL,
    org_id uuid,
    CONSTRAINT actor_memory_value_format_known CHECK ((value_format = ANY (ARRAY[0, 1, 3, 4]))),
    CONSTRAINT agent_runtime_memory_memory_type_check CHECK ((memory_type = ANY (ARRAY['working'::text, 'episodic'::text, 'semantic'::text, 'scratchpad'::text])))
);


--
-- Name: actors; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.actors (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    name text NOT NULL,
    description text,
    status text DEFAULT 'active'::text NOT NULL,
    max_capability_world text DEFAULT 'minimal-node'::text NOT NULL,
    secret_grants text[] DEFAULT '{}'::text[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    metadata jsonb,
    max_llm_tier text DEFAULT 'tier2'::text NOT NULL,
    org_id uuid,
    is_default boolean DEFAULT false NOT NULL,
    egress_scope text DEFAULT NULL,
    CONSTRAINT actors_egress_scope_check CHECK ((egress_scope IS NULL OR (egress_scope = ANY (ARRAY['local'::text, 'public'::text])))),
    CONSTRAINT actors_max_llm_tier_check CHECK ((max_llm_tier = ANY (ARRAY['tier1'::text, 'tier2'::text]))),
    CONSTRAINT actors_status_check CHECK ((status = ANY (ARRAY['active'::text, 'suspended'::text, 'terminated'::text, 'archived'::text])))
);

ALTER TABLE ONLY public.actors FORCE ROW LEVEL SECURITY;


--
-- Name: admin_event_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.admin_event_log (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid,
    event_type text NOT NULL,
    resource_type text NOT NULL,
    resource_id uuid,
    summary text NOT NULL,
    details jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: agent_roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_roles (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    description text,
    allowed_capabilities text[] DEFAULT '{}'::text[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    allowed_sql_operations text[] DEFAULT '{}'::text[],
    CONSTRAINT chk_known_capabilities CHECK ((allowed_capabilities <@ ARRAY['*'::text, 'admin'::text, 'minimal'::text, 'minimal-node'::text, 'automation'::text, 'automation-node'::text, 'network'::text, 'network-node'::text, 'secrets'::text, 'secrets-node'::text, 'filesystem'::text, 'filesystem-node'::text, 'messaging'::text, 'messaging-node'::text, 'database'::text, 'database-node'::text, 'cache'::text, 'cache-node'::text, 'governance'::text, 'governance-node'::text, 'http'::text, 'http-node'::text, 'llm-inference'::text, 'llm-inference-node'::text, 'agent'::text, 'agent-node'::text, 'trusted'::text, 'trusted-node'::text]))
);


--
-- Name: api_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.api_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    name text NOT NULL,
    key_hash text NOT NULL,
    key_prefix text NOT NULL,
    scopes text[] DEFAULT '{}'::text[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    is_active boolean DEFAULT true NOT NULL,
    usage_count integer DEFAULT 0 NOT NULL,
    org_id uuid
);


--
-- Name: atlassian_integrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.atlassian_integrations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    cloud_id character varying(255) NOT NULL,
    site_url text NOT NULL,
    display_name text,
    scope text,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    account_id character varying(255),
    org_id uuid
);


--
-- Name: audit_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_events (
    id bigint NOT NULL,
    workflow_id uuid NOT NULL,
    execution_id uuid NOT NULL,
    sequence_num bigint NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    actor text NOT NULL,
    action text NOT NULL,
    payload text NOT NULL,
    previous_hash text NOT NULL,
    event_hash text NOT NULL
);


--
-- Name: audit_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.audit_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.audit_events_id_seq OWNED BY public.audit_events.id;


--
-- Name: auth_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_audit_log (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid,
    event_type text NOT NULL,
    email text,
    ip_address text,
    user_agent text,
    success boolean NOT NULL,
    failure_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: circuit_breaker_metrics; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.circuit_breaker_metrics (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    service_name text NOT NULL,
    state text NOT NULL,
    failure_count integer DEFAULT 0 NOT NULL,
    success_count integer DEFAULT 0 NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: compilation_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.compilation_cache (
    source_hash text NOT NULL,
    module_id uuid,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: dead_letter_jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dead_letter_jobs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    original_job_id uuid NOT NULL,
    payload jsonb NOT NULL,
    user_id uuid NOT NULL,
    error_message text NOT NULL,
    failed_at timestamp with time zone DEFAULT now() NOT NULL,
    org_id uuid
);


--
-- Name: dead_letter_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dead_letter_queue (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workflow_id uuid NOT NULL,
    execution_id uuid NOT NULL,
    node_id uuid NOT NULL,
    error_message text NOT NULL,
    payload jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    replayed_at timestamp with time zone,
    replayed_by uuid
);


--
-- Name: encryption_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.encryption_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    algorithm text DEFAULT 'AES-256-GCM'::text NOT NULL,
    active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    encrypted_key bytea NOT NULL,
    org_id uuid
);


--
-- Name: execution_approvals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.execution_approvals (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workflow_id uuid NOT NULL,
    execution_id uuid NOT NULL,
    node_id uuid NOT NULL,
    required_for text[] DEFAULT '{}'::text[] NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    requested_at timestamp with time zone DEFAULT now() NOT NULL,
    decided_at timestamp with time zone,
    decided_by uuid,
    reason text,
    org_id uuid,
    CONSTRAINT execution_approvals_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'approved'::text, 'denied'::text])))
);


--
-- Name: execution_cost_rollup; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.execution_cost_rollup (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    actor_id uuid,
    workflow_id uuid NOT NULL,
    execution_id uuid NOT NULL,
    node_id text NOT NULL,
    module_id uuid,
    fuel_consumed bigint DEFAULT 0 NOT NULL,
    wall_time_ms bigint DEFAULT 0 NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    org_id uuid
);


--
-- Name: execution_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.execution_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    execution_id uuid NOT NULL,
    event_type text NOT NULL,
    node_id uuid,
    status text NOT NULL,
    log_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    iteration_index integer,
    iteration_total integer,
    duration_ms bigint,
    error_class text,
    org_id uuid,
    CONSTRAINT execution_events_event_type_check CHECK ((event_type = ANY (ARRAY['started'::text, 'node_started'::text, 'node_completed'::text, 'node_failed'::text, 'node_skipped'::text, 'node_waiting'::text, 'node_retrying'::text, 'retry_skipped'::text, 'node_input'::text, 'completed'::text, 'failed'::text, 'skipped'::text, 'waiting'::text, 'pending'::text, 'loop_iteration'::text]))),
    CONSTRAINT execution_events_status_check CHECK ((status = ANY (ARRAY['Running'::text, 'Completed'::text, 'Failed'::text, 'Skipped'::text, 'Input'::text])))
);


--
-- Name: execution_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.execution_state (
    execution_id uuid NOT NULL,
    key text NOT NULL,
    value text NOT NULL,
    version bigint DEFAULT 1 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    org_id uuid
);


--
-- Name: feature_flags; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.feature_flags (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    description text NOT NULL,
    value jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid NOT NULL
);


--
-- Name: github_app_installations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.github_app_installations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    installation_id bigint NOT NULL,
    account_login text NOT NULL,
    account_type text,
    permissions jsonb,
    repository_selection text,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: gmail_integrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.gmail_integrations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    email_address text NOT NULL,
    account_name text,
    token_expires_at timestamp with time zone,
    scope text,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    org_id uuid
);


--
-- Name: google_calendar_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.google_calendar_audit_log (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    integration_id uuid,
    user_id uuid,
    event_type character varying(50) NOT NULL,
    calendar_id character varying(255),
    success boolean NOT NULL,
    error_message text,
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: google_calendar_integrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.google_calendar_integrations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    oauth_account_id uuid NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    scope text NOT NULL,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    org_id uuid
);


--
-- Name: google_calendar_watch_channels; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.google_calendar_watch_channels (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    integration_id uuid NOT NULL,
    calendar_id character varying(255) NOT NULL,
    channel_id character varying(255) NOT NULL,
    resource_id character varying(255) NOT NULL,
    webhook_url text NOT NULL,
    expiration timestamp with time zone NOT NULL,
    sync_token text,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    verification_token text NOT NULL,
    last_message_number bigint DEFAULT 0,
    module_id uuid
);


--
-- Name: idempotency_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.idempotency_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    key text NOT NULL,
    request_hash text NOT NULL,
    response_body text,
    status_code integer NOT NULL,
    user_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    org_id uuid
);


--
-- Name: integration_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_credentials (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    provider character varying(50) NOT NULL,
    provider_key character varying(255) NOT NULL,
    access_token_secret_path text,
    refresh_token_secret_path text,
    token_expires_at timestamp with time zone,
    scope text,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    org_id uuid
);


--
-- Name: integration_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_state (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    integration_name text NOT NULL,
    user_id uuid NOT NULL,
    key text NOT NULL,
    value jsonb,
    expires_at timestamp with time zone,
    idx_str_1 text,
    idx_str_2 text,
    idx_ts_1 timestamp with time zone,
    idx_int_1 bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    org_id uuid,
    value_enc bytea,
    value_key_id uuid,
    value_format smallint,
    CONSTRAINT integration_state_enc_columns_together CHECK ((((value_enc IS NULL) AND (value_key_id IS NULL) AND (value_format IS NULL)) OR ((value_enc IS NOT NULL) AND (value_key_id IS NOT NULL) AND (value_format IS NOT NULL)))),
    CONSTRAINT integration_state_key_not_empty CHECK (((length(key) > 0) AND (length(key) <= 256))),
    CONSTRAINT integration_state_name_not_empty CHECK (((length(integration_name) > 0) AND (length(integration_name) <= 64))),
    CONSTRAINT integration_state_value_format_valid CHECK (((value_format IS NULL) OR (value_format = ANY (ARRAY[3, 4])))),
    CONSTRAINT integration_state_value_xor_enc CHECK (((value IS NOT NULL) <> (value_enc IS NOT NULL)))
);


--
-- Name: jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.jobs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    payload jsonb NOT NULL,
    priority integer DEFAULT 2 NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    user_id uuid NOT NULL,
    organization_id uuid,
    retry_count integer DEFAULT 0 NOT NULL,
    max_retries integer DEFAULT 3 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    scheduled_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    error_message text,
    worker_id text,
    org_id uuid
);


--
-- Name: key_rotation_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.key_rotation_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    old_key_version integer NOT NULL,
    new_key_version integer NOT NULL,
    rotated_at timestamp with time zone DEFAULT now() NOT NULL,
    rotated_by uuid,
    reason text,
    secrets_migrated integer DEFAULT 0 NOT NULL
);


--
-- Name: mcp_agents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_agents (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    description text,
    role_id uuid NOT NULL,
    token_hash text NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    last_connected_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    user_id uuid,
    token_lookup_hash text,
    org_id uuid
);


--
-- Name: mcp_crate_allowlist; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mcp_crate_allowlist (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    crate_name text NOT NULL,
    max_version text,
    org_id uuid,
    is_global boolean DEFAULT false NOT NULL,
    added_by uuid,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: module_execution_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.module_execution_logs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    execution_id uuid NOT NULL,
    level text NOT NULL,
    message text NOT NULL,
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT node_execution_logs_level_check CHECK ((level = ANY (ARRAY['DEBUG'::text, 'INFO'::text, 'WARN'::text, 'ERROR'::text])))
);


--
-- Name: module_executions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.module_executions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    module_id uuid NOT NULL,
    user_id uuid NOT NULL,
    status text NOT NULL,
    trigger_type text NOT NULL,
    trigger_metadata jsonb,
    input_data jsonb,
    output_data jsonb,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    duration_ms integer,
    error_message text,
    error_type text,
    fuel_consumed bigint,
    memory_used_mb integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    log_count integer DEFAULT 0,
    workflow_execution_id uuid,
    input_data_enc bytea,
    output_data_enc bytea,
    trigger_metadata_enc bytea,
    payload_enc_key_id uuid,
    payload_format smallint DEFAULT 0 NOT NULL,
    org_id uuid,
    actor_id uuid NOT NULL,
    CONSTRAINT module_executions_payload_format_known CHECK ((payload_format = ANY (ARRAY[0, 1, 2, 3, 4]))),
    CONSTRAINT node_executions_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'running'::text, 'completed'::text, 'failed'::text, 'timeout'::text, 'cancelled'::text]))),
    CONSTRAINT node_executions_trigger_type_check CHECK ((trigger_type = ANY (ARRAY['webhook'::text, 'manual'::text, 'scheduled'::text, 'test'::text])))
);


--
-- Name: module_marketplace; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.module_marketplace (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    module_id uuid NOT NULL,
    publisher_id uuid NOT NULL,
    name text NOT NULL,
    description text,
    capability_world text NOT NULL,
    version text DEFAULT '1.0.0'::text NOT NULL,
    downloads integer DEFAULT 0 NOT NULL,
    is_public boolean DEFAULT true NOT NULL,
    tags text[] DEFAULT '{}'::text[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    verified boolean DEFAULT false NOT NULL,
    star_count integer DEFAULT 0 NOT NULL
);


--
-- Name: module_marketplace_stars; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.module_marketplace_stars (
    user_id uuid NOT NULL,
    listing_id uuid NOT NULL,
    starred_at timestamp with time zone DEFAULT now() NOT NULL,
    org_id uuid
);


--
-- Name: module_update_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.module_update_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    module_id uuid NOT NULL,
    user_id uuid NOT NULL,
    previous_hash text,
    new_hash text NOT NULL,
    size_bytes integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    org_id uuid
);


--
-- Name: modules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.modules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid,
    name text NOT NULL,
    kind text NOT NULL,
    display_name text,
    description text,
    capability_world text DEFAULT 'minimal-node'::text NOT NULL,
    config_schema jsonb DEFAULT '{}'::jsonb NOT NULL,
    input_schema jsonb,
    output_schema jsonb,
    allowed_hosts text[] DEFAULT '{}'::text[] NOT NULL,
    allowed_methods text[] DEFAULT '{}'::text[] NOT NULL,
    allowed_secrets text[] DEFAULT '{}'::text[] NOT NULL,
    requires_approval_for text[] DEFAULT '{}'::text[] NOT NULL,
    max_retries integer DEFAULT 0 NOT NULL,
    retry_backoff_ms bigint DEFAULT 500 NOT NULL,
    rate_limit_per_minute integer,
    source_code text,
    wasm_bytes bytea,
    content_hash text,
    size_bytes integer,
    max_fuel bigint DEFAULT 2000000,
    oci_url text,
    integration_name text,
    language text DEFAULT 'rust'::text NOT NULL,
    usage_count bigint DEFAULT 0 NOT NULL,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    compiled_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    max_memory_mb integer DEFAULT 128 NOT NULL,
    imported_interfaces text[] DEFAULT '{}'::text[] NOT NULL,
    dependencies jsonb,
    config jsonb,
    category text,
    org_id uuid,
    CONSTRAINT modules_integration_name_check CHECK (((integration_name IS NULL) OR ((length(integration_name) >= 1) AND (length(integration_name) <= 64) AND (integration_name ~ '^[a-z0-9_-]+$'::text)))),
    CONSTRAINT modules_kind_check CHECK ((kind = ANY (ARRAY['catalog'::text, 'sandbox'::text, 'extracted'::text])))
);


--
-- Name: node_result_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.node_result_cache (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    cache_key text NOT NULL,
    module_hash text NOT NULL,
    module_version text DEFAULT '1.0.0'::text NOT NULL,
    input_hash text NOT NULL,
    output_json jsonb NOT NULL,
    fuel_consumed bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_hit_at timestamp with time zone DEFAULT now() NOT NULL,
    hit_count bigint DEFAULT 0 NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '7 days'::interval) NOT NULL
);


--
-- Name: oauth_accounts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_accounts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    provider text NOT NULL,
    provider_user_id text NOT NULL,
    email text NOT NULL,
    name text,
    picture_url text,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    last_login_at timestamp with time zone
);


--
-- Name: oauth_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_audit_log (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid,
    provider text NOT NULL,
    event_type text NOT NULL,
    success boolean NOT NULL,
    error_message text,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: oauth_state_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_state_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    state_token text NOT NULL,
    provider text NOT NULL,
    used boolean DEFAULT false,
    expires_at timestamp with time zone DEFAULT (now() + '00:10:00'::interval) NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    pkce_verifier text,
    user_id uuid,
    session_binding_hash text
);


--
-- Name: organization_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organization_members (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role character varying(50) DEFAULT 'member'::character varying NOT NULL,
    invited_by uuid,
    joined_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT chk_org_members_role CHECK (((role)::text = ANY (ARRAY[('owner'::character varying)::text, ('admin'::character varying)::text, ('member'::character varying)::text, ('viewer'::character varying)::text])))
);


--
-- Name: organizations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organizations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    slug character varying(100) NOT NULL,
    owner_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    is_personal boolean DEFAULT false NOT NULL
);


--
-- Name: resource_quotas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.resource_quotas (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    org_id uuid NOT NULL,
    metric text NOT NULL,
    max_limit bigint DEFAULT 0 NOT NULL,
    current_usage bigint DEFAULT 0 NOT NULL,
    resets_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: rotated_session_audit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.rotated_session_audit (
    lookup_hash text NOT NULL,
    user_id uuid NOT NULL,
    rotated_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL
);


--
-- Name: schema_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schema_audit_log (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    event_time timestamp with time zone DEFAULT now() NOT NULL,
    schema_name text,
    object_type text,
    object_name text,
    command_tag text,
    client_addr inet,
    client_port integer,
    db_user text,
    application_name text,
    query text
);


--
-- Name: scratch_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scratch_sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    name text NOT NULL,
    code text NOT NULL,
    world text DEFAULT 'minimal-node'::text NOT NULL,
    last_output jsonb,
    last_error text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    org_id uuid
);

ALTER TABLE ONLY public.scratch_sessions FORCE ROW LEVEL SECURITY;


--
-- Name: secret_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.secret_audit_log (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    secret_id uuid,
    action text NOT NULL,
    actor_type text NOT NULL,
    actor_id uuid,
    module_id uuid,
    success boolean NOT NULL,
    failure_reason text,
    ip_address text,
    "timestamp" timestamp with time zone DEFAULT now(),
    error_message text,
    org_id uuid
);


--
-- Name: secrets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.secrets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    key_path text NOT NULL,
    description text,
    encrypted_value bytea NOT NULL,
    encryption_key_id uuid NOT NULL,
    allowed_modules uuid[],
    created_by uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    last_accessed_at timestamp with time zone,
    access_count integer DEFAULT 0,
    user_id uuid,
    nonce bytea,
    expires_at timestamp with time zone,
    owner_user_id uuid,
    org_id uuid,
    key_version integer DEFAULT 1 NOT NULL,
    rotation_reminder_days integer,
    namespace text DEFAULT 'default'::text NOT NULL,
    encryption_format_version smallint DEFAULT 0 NOT NULL,
    CONSTRAINT secrets_encryption_format_version_known CHECK ((encryption_format_version = ANY (ARRAY[0, 1, 3, 4])))
);

ALTER TABLE ONLY public.secrets FORCE ROW LEVEL SECURITY;


--
-- Name: secrets_rotation_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.secrets_rotation_log (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    key_type text NOT NULL,
    key_id text NOT NULL,
    rotated_at timestamp with time zone DEFAULT now() NOT NULL,
    rotated_by uuid,
    expires_at timestamp with time zone,
    reason text
);


--
-- Name: semantic_execution_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.semantic_execution_cache (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workflow_id uuid NOT NULL,
    input_hash text NOT NULL,
    input_embedding public.vector(1024),
    input_json jsonb NOT NULL,
    output_json jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    hit_count integer DEFAULT 0 NOT NULL,
    org_id uuid
);


--
-- Name: slack_integration_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.slack_integration_audit_log (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    integration_id uuid,
    user_id uuid,
    event_type character varying(50) NOT NULL,
    success boolean NOT NULL,
    error_message text,
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: slack_integrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.slack_integrations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    team_id character varying(255) NOT NULL,
    team_name character varying(255) NOT NULL,
    team_domain character varying(255),
    bot_user_id character varying(255),
    app_id character varying(255),
    scope text,
    verification_token character varying(255),
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    last_used_at timestamp with time zone,
    org_id uuid
);


--
-- Name: system_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.system_settings (
    key text NOT NULL,
    value jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: tenant_quotas; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_quotas (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    max_workflows integer DEFAULT 100 NOT NULL,
    max_executions integer DEFAULT 50 NOT NULL,
    max_secrets integer DEFAULT 100 NOT NULL,
    api_rate_limit integer DEFAULT 1000 NOT NULL,
    max_fuel_per_execution bigint DEFAULT 100000 NOT NULL,
    max_memory_per_execution integer DEFAULT 256 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: user_audit_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_audit_settings (
    user_id uuid NOT NULL,
    streaming_enabled boolean DEFAULT false NOT NULL,
    otlp_endpoint text,
    otlp_protocol text,
    auth_headers_encrypted bytea,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    auth_headers_enc_key_id uuid,
    auth_headers_format smallint DEFAULT 0 NOT NULL,
    CONSTRAINT user_audit_settings_otlp_protocol_check CHECK ((otlp_protocol = ANY (ARRAY['grpc'::text, 'http'::text])))
);


--
-- Name: user_capability_grants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_capability_grants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    max_capability_world text DEFAULT 'http-node'::text NOT NULL,
    granted_by uuid,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    notes text,
    CONSTRAINT ucg_world_check CHECK ((max_capability_world = ANY (ARRAY['minimal-node'::text, 'http-node'::text, 'standard-node'::text, 'network-node'::text, 'secrets-node'::text, 'governance-node'::text, 'messaging-node'::text, 'filesystem-node'::text, 'cache-node'::text, 'database-node'::text, 'automation-node'::text, 'full-node'::text])))
);


--
-- Name: user_module_pins; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_module_pins (
    user_id uuid NOT NULL,
    module_name text NOT NULL,
    pinned_at timestamp with time zone DEFAULT now() NOT NULL,
    org_id uuid
);

ALTER TABLE ONLY public.user_module_pins FORCE ROW LEVEL SECURITY;


--
-- Name: user_modules; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.user_modules AS
 SELECT id,
    name,
    user_id,
    capability_world,
    compiled_at,
    id AS template_id,
    source_code,
        CASE
            WHEN (kind = 'catalog'::text) THEN 'catalog'::text
            WHEN (kind = 'extracted'::text) THEN 'extracted'::text
            ELSE 'sandbox'::text
        END AS source
   FROM public.modules m
  WHERE (user_id IS NOT NULL);


--
-- Name: user_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    refresh_token_hash text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    refresh_token_lookup_hash text,
    is_2fa_verified boolean DEFAULT false NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email text NOT NULL,
    password_hash text NOT NULL,
    name text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_login_at timestamp with time zone,
    is_active boolean DEFAULT true NOT NULL,
    failed_login_attempts integer DEFAULT 0 NOT NULL,
    locked_until timestamp with time zone,
    totp_secret text,
    totp_enabled boolean DEFAULT false NOT NULL,
    backup_codes text[],
    is_platform_admin boolean DEFAULT false NOT NULL,
    totp_secret_format smallint DEFAULT 0 NOT NULL,
    CONSTRAINT users_totp_secret_format_known CHECK ((totp_secret_format = ANY (ARRAY[0, 1, 3, 4])))
);


--
-- Name: webhook_dlq; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_dlq (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    trigger_id uuid,
    source_ip inet,
    drop_reason text NOT NULL,
    headers jsonb,
    payload jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    replayed_at timestamp with time zone,
    replayed_by uuid
);


--
-- Name: webhook_processed_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_processed_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    trigger_id uuid NOT NULL,
    event_id text NOT NULL,
    processed_at timestamp with time zone DEFAULT now() NOT NULL,
    org_id uuid
);


--
-- Name: webhook_request_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_request_log (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    trigger_id uuid,
    method text NOT NULL,
    headers jsonb,
    body text,
    source_ip text,
    user_agent text,
    response_status integer,
    response_time_ms integer,
    success boolean,
    error_message text,
    created_at timestamp with time zone DEFAULT now(),
    status_code integer,
    response_body text,
    wasm_execution_ms integer,
    org_id uuid
);


--
-- Name: webhook_triggers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_triggers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    module_id uuid,
    verification_token text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    max_requests_per_minute integer DEFAULT 60 NOT NULL,
    trigger_count integer DEFAULT 0,
    success_count integer DEFAULT 0,
    error_count integer DEFAULT 0,
    last_triggered_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    user_id uuid,
    allowed_ips text[],
    auto_respond boolean DEFAULT false,
    queue_events boolean DEFAULT false,
    avg_response_ms integer,
    log_body boolean DEFAULT true NOT NULL,
    signing_secret_enc bytea,
    signing_key_id uuid,
    workflow_id uuid,
    sync_response boolean DEFAULT false NOT NULL,
    sync_timeout_secs integer DEFAULT 30 NOT NULL,
    signing_secret_format smallint DEFAULT 0 NOT NULL,
    org_id uuid,
    event_filter jsonb,
    CONSTRAINT webhook_triggers_signing_secret_format_known CHECK ((signing_secret_format = ANY (ARRAY[0, 1, 3, 4])))
);


--
-- Name: worker_identities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.worker_identities (
    worker_id text NOT NULL,
    public_key bytea NOT NULL,
    key_algo text DEFAULT 'ed25519'::text NOT NULL,
    supports_sealing boolean DEFAULT false NOT NULL,
    active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT worker_identities_key_algo CHECK ((key_algo = 'ed25519'::text)),
    CONSTRAINT worker_identities_public_key_len CHECK ((octet_length(public_key) = 32))
);


--
-- Name: worker_provisioning_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.worker_provisioning_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    token_hash text NOT NULL,
    worker_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    used_by_worker_id text,
    revoked_at timestamp with time zone,
    note text,
    CONSTRAINT worker_provisioning_tokens_hash_len CHECK ((char_length(token_hash) = 64))
);


--
-- Name: workflow_alerts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workflow_alerts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    workflow_id uuid NOT NULL,
    execution_id uuid NOT NULL,
    alert_type text DEFAULT 'execution_failed'::text NOT NULL,
    message text NOT NULL,
    acknowledged boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    occurrence_count integer DEFAULT 1 NOT NULL,
    last_occurred_at timestamp with time zone DEFAULT now() NOT NULL,
    workflow_name text,
    org_id uuid
);


--
-- Name: workflow_approval_gates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workflow_approval_gates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    title text NOT NULL,
    description text,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    token text NOT NULL,
    continuation_workflow_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '7 days'::interval) NOT NULL,
    resolved_at timestamp with time zone,
    resolved_by_type text,
    resolved_by_note text,
    continuation_execution_id uuid,
    notification_webhook text,
    org_id uuid,
    token_hash text GENERATED ALWAYS AS (encode(public.digest(token, 'sha256'::text), 'hex'::text)) STORED,
    CONSTRAINT workflow_approval_gates_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'approved'::text, 'rejected'::text, 'expired'::text, 'cancelled'::text])))
);


--
-- Name: workflow_execution_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workflow_execution_logs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    execution_id uuid NOT NULL,
    node_id uuid,
    level text NOT NULL,
    message text NOT NULL,
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT workflow_execution_logs_level_check CHECK ((level = ANY (ARRAY['DEBUG'::text, 'INFO'::text, 'WARN'::text, 'ERROR'::text])))
);


--
-- Name: workflow_executions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workflow_executions (
    id uuid NOT NULL,
    workflow_id uuid NOT NULL,
    user_id uuid NOT NULL,
    status text NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    error_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    output_data jsonb,
    checkpoint_data jsonb,
    workflow_version_id uuid,
    is_test_execution boolean DEFAULT false NOT NULL,
    checkpoint_encrypted bytea,
    checkpoint_nonce bytea,
    is_pinned boolean DEFAULT false NOT NULL,
    pin_note text,
    priority text DEFAULT 'normal'::text NOT NULL,
    replayed_from_id uuid,
    input_data jsonb,
    actor_id uuid NOT NULL,
    provenance jsonb,
    acknowledged_at timestamp with time zone,
    acknowledgement_reason text,
    parent_execution_id uuid,
    root_execution_id uuid,
    output_data_enc bytea,
    output_enc_key_id uuid,
    output_data_format smallint DEFAULT 0 NOT NULL,
    org_id uuid,
    checkpoint_seq bigint DEFAULT 0 NOT NULL,
    epoch bigint DEFAULT 0 NOT NULL,
    CONSTRAINT workflow_executions_output_data_format_known CHECK ((output_data_format = ANY (ARRAY[0, 1, 3, 4]))),
    CONSTRAINT workflow_executions_status_check CHECK ((status = ANY (ARRAY['running'::text, 'completed'::text, 'failed'::text, 'cancelled'::text, 'queued'::text, 'waiting'::text, 'resuming'::text])))
);

ALTER TABLE ONLY public.workflow_executions FORCE ROW LEVEL SECURITY;


--
-- Name: workflow_executions_archive; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workflow_executions_archive (
    id uuid NOT NULL,
    workflow_id uuid NOT NULL,
    user_id uuid NOT NULL,
    status text NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    error_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    output_data jsonb,
    checkpoint_data jsonb,
    workflow_version_id uuid,
    is_test_execution boolean DEFAULT false NOT NULL,
    checkpoint_encrypted bytea,
    checkpoint_nonce bytea,
    is_pinned boolean DEFAULT false NOT NULL,
    pin_note text,
    priority text DEFAULT 'normal'::text NOT NULL,
    replayed_from_id uuid,
    input_data jsonb,
    acknowledged_at timestamp with time zone,
    acknowledgement_reason text,
    actor_id uuid,
    provenance jsonb,
    org_id uuid,
    CONSTRAINT workflow_executions_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'running'::text, 'completed'::text, 'failed'::text, 'cancelled'::text])))
);


--
-- Name: workflow_module_refs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workflow_module_refs (
    workflow_id uuid NOT NULL,
    module_id uuid NOT NULL
);


--
-- Name: workflow_nodes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workflow_nodes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workflow_id uuid,
    module_id uuid,
    position_x double precision NOT NULL,
    position_y double precision NOT NULL,
    config jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    org_id uuid
);


--
-- Name: workflow_reuse_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workflow_reuse_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workflow_id uuid NOT NULL,
    caller_session text,
    invocation_type text DEFAULT 'trigger'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: workflow_schedules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workflow_schedules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workflow_id uuid NOT NULL,
    user_id uuid NOT NULL,
    cron_expression character varying(255) NOT NULL,
    timezone character varying(64) DEFAULT 'UTC'::character varying NOT NULL,
    is_enabled boolean DEFAULT true NOT NULL,
    last_triggered_at timestamp with time zone,
    next_trigger_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    org_id uuid
);


--
-- Name: workflow_sla_thresholds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workflow_sla_thresholds (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workflow_id uuid NOT NULL,
    user_id uuid NOT NULL,
    p95_latency_ms bigint,
    success_rate_pct numeric(5,2),
    notification_webhook text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    org_id uuid
);


--
-- Name: workflow_suspensions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workflow_suspensions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    execution_id uuid,
    correlation_id text NOT NULL,
    description text,
    continuation_workflow_id uuid,
    state jsonb,
    status text DEFAULT 'waiting'::text NOT NULL,
    timeout_at timestamp with time zone,
    resumed_at timestamp with time zone,
    resumed_by text,
    resumed_payload jsonb,
    callback_url text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    org_id uuid,
    CONSTRAINT workflow_suspensions_status_check CHECK ((status = ANY (ARRAY['waiting'::text, 'resumed'::text, 'expired'::text, 'cancelled'::text])))
);


--
-- Name: workflow_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workflow_versions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    workflow_id uuid NOT NULL,
    version_number integer NOT NULL,
    graph_json jsonb NOT NULL,
    description text,
    published_at timestamp with time zone DEFAULT now() NOT NULL,
    published_by uuid NOT NULL,
    is_active boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    graph_hash text,
    graph_signature text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    org_id uuid
);


--
-- Name: workflows; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.workflows (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    module_uri text NOT NULL,
    graph_json text NOT NULL,
    user_id uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    org_id uuid,
    tags text[] DEFAULT '{}'::text[] NOT NULL,
    description text,
    failure_webhook_url text,
    max_concurrent_executions integer,
    is_enabled boolean DEFAULT true NOT NULL,
    capabilities text[] DEFAULT '{}'::text[] NOT NULL,
    intent jsonb,
    readiness_score integer,
    readiness_computed_at timestamp with time zone,
    search_text text,
    embedding public.vector(1024),
    status character varying(20) DEFAULT 'draft'::character varying NOT NULL,
    actor_id uuid,
    input_schema jsonb,
    workflow_type text DEFAULT 'production'::text NOT NULL,
    timeout_seconds integer,
    readiness_scored_at timestamp with time zone,
    CONSTRAINT workflows_workflow_type_check CHECK ((workflow_type = ANY (ARRAY['production'::text, 'internal'::text, 'test'::text, 'template'::text])))
);

ALTER TABLE ONLY public.workflows FORCE ROW LEVEL SECURITY;


--
-- Name: audit_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events ALTER COLUMN id SET DEFAULT nextval('public.audit_events_id_seq'::regclass);


--
-- Name: _sqlx_migrations _sqlx_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public._sqlx_migrations
    ADD CONSTRAINT _sqlx_migrations_pkey PRIMARY KEY (version);


--
-- Name: admin_event_log admin_event_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.admin_event_log
    ADD CONSTRAINT admin_event_log_pkey PRIMARY KEY (id);


--
-- Name: actor_action_log agent_action_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.actor_action_log
    ADD CONSTRAINT agent_action_log_pkey PRIMARY KEY (id);


--
-- Name: actor_approval_policies agent_approval_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.actor_approval_policies
    ADD CONSTRAINT agent_approval_policies_pkey PRIMARY KEY (id);


--
-- Name: actor_budget_policies agent_budget_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.actor_budget_policies
    ADD CONSTRAINT agent_budget_policies_pkey PRIMARY KEY (actor_id);


--
-- Name: agent_roles agent_roles_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_roles
    ADD CONSTRAINT agent_roles_name_key UNIQUE (name);


--
-- Name: agent_roles agent_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_roles
    ADD CONSTRAINT agent_roles_pkey PRIMARY KEY (id);


--
-- Name: actor_memory agent_runtime_memory_agent_id_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.actor_memory
    ADD CONSTRAINT agent_runtime_memory_agent_id_key_key UNIQUE (actor_id, key);


--
-- Name: actor_memory agent_runtime_memory_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.actor_memory
    ADD CONSTRAINT agent_runtime_memory_pkey PRIMARY KEY (id);


--
-- Name: actors agents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.actors
    ADD CONSTRAINT agents_pkey PRIMARY KEY (id);


--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);


--
-- Name: atlassian_integrations atlassian_integrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.atlassian_integrations
    ADD CONSTRAINT atlassian_integrations_pkey PRIMARY KEY (id);


--
-- Name: atlassian_integrations atlassian_integrations_user_id_cloud_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.atlassian_integrations
    ADD CONSTRAINT atlassian_integrations_user_id_cloud_id_key UNIQUE (user_id, cloud_id);


--
-- Name: audit_events audit_events_execution_id_sequence_num_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_execution_id_sequence_num_key UNIQUE (execution_id, sequence_num);


--
-- Name: audit_events audit_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_pkey PRIMARY KEY (id);


--
-- Name: auth_audit_log auth_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_audit_log
    ADD CONSTRAINT auth_audit_log_pkey PRIMARY KEY (id);


--
-- Name: circuit_breaker_metrics circuit_breaker_metrics_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.circuit_breaker_metrics
    ADD CONSTRAINT circuit_breaker_metrics_pkey PRIMARY KEY (id);


--
-- Name: compilation_cache compilation_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compilation_cache
    ADD CONSTRAINT compilation_cache_pkey PRIMARY KEY (source_hash);


--
-- Name: dead_letter_jobs dead_letter_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dead_letter_jobs
    ADD CONSTRAINT dead_letter_jobs_pkey PRIMARY KEY (id);


--
-- Name: dead_letter_queue dead_letter_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dead_letter_queue
    ADD CONSTRAINT dead_letter_queue_pkey PRIMARY KEY (id);


--
-- Name: encryption_keys encryption_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.encryption_keys
    ADD CONSTRAINT encryption_keys_pkey PRIMARY KEY (id);


--
-- Name: execution_approvals execution_approvals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.execution_approvals
    ADD CONSTRAINT execution_approvals_pkey PRIMARY KEY (id);


--
-- Name: execution_cost_rollup execution_cost_rollup_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.execution_cost_rollup
    ADD CONSTRAINT execution_cost_rollup_pkey PRIMARY KEY (id);


--
-- Name: execution_events execution_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.execution_events
    ADD CONSTRAINT execution_events_pkey PRIMARY KEY (id);


--
-- Name: execution_state execution_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.execution_state
    ADD CONSTRAINT execution_state_pkey PRIMARY KEY (execution_id, key);


--
-- Name: feature_flags feature_flags_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feature_flags
    ADD CONSTRAINT feature_flags_name_key UNIQUE (name);


--
-- Name: feature_flags feature_flags_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feature_flags
    ADD CONSTRAINT feature_flags_pkey PRIMARY KEY (id);


--
-- Name: github_app_installations github_app_installations_installation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.github_app_installations
    ADD CONSTRAINT github_app_installations_installation_id_key UNIQUE (installation_id);


--
-- Name: github_app_installations github_app_installations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.github_app_installations
    ADD CONSTRAINT github_app_installations_pkey PRIMARY KEY (id);


--
-- Name: gmail_integrations gmail_integrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.gmail_integrations
    ADD CONSTRAINT gmail_integrations_pkey PRIMARY KEY (id);


--
-- Name: gmail_integrations gmail_integrations_user_id_email_address_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.gmail_integrations
    ADD CONSTRAINT gmail_integrations_user_id_email_address_key UNIQUE (user_id, email_address);


--
-- Name: google_calendar_audit_log google_calendar_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.google_calendar_audit_log
    ADD CONSTRAINT google_calendar_audit_log_pkey PRIMARY KEY (id);


--
-- Name: google_calendar_integrations google_calendar_integrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.google_calendar_integrations
    ADD CONSTRAINT google_calendar_integrations_pkey PRIMARY KEY (id);


--
-- Name: google_calendar_integrations google_calendar_integrations_user_id_oauth_account_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.google_calendar_integrations
    ADD CONSTRAINT google_calendar_integrations_user_id_oauth_account_id_key UNIQUE (user_id, oauth_account_id);


--
-- Name: google_calendar_watch_channels google_calendar_watch_channels_channel_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.google_calendar_watch_channels
    ADD CONSTRAINT google_calendar_watch_channels_channel_id_key UNIQUE (channel_id);


--
-- Name: google_calendar_watch_channels google_calendar_watch_channels_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.google_calendar_watch_channels
    ADD CONSTRAINT google_calendar_watch_channels_pkey PRIMARY KEY (id);


--
-- Name: idempotency_keys idempotency_keys_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.idempotency_keys
    ADD CONSTRAINT idempotency_keys_key_key UNIQUE (key);


--
-- Name: idempotency_keys idempotency_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.idempotency_keys
    ADD CONSTRAINT idempotency_keys_pkey PRIMARY KEY (id);


--
-- Name: integration_credentials integration_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_credentials
    ADD CONSTRAINT integration_credentials_pkey PRIMARY KEY (id);


--
-- Name: integration_credentials integration_credentials_user_id_provider_provider_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_credentials
    ADD CONSTRAINT integration_credentials_user_id_provider_provider_key_key UNIQUE (user_id, provider, provider_key);


--
-- Name: integration_state integration_state_key_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_state
    ADD CONSTRAINT integration_state_key_unique UNIQUE (integration_name, user_id, key);


--
-- Name: integration_state integration_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_state
    ADD CONSTRAINT integration_state_pkey PRIMARY KEY (id);


--
-- Name: jobs jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jobs
    ADD CONSTRAINT jobs_pkey PRIMARY KEY (id);


--
-- Name: key_rotation_events key_rotation_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.key_rotation_events
    ADD CONSTRAINT key_rotation_events_pkey PRIMARY KEY (id);


--
-- Name: mcp_agents mcp_agents_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_agents
    ADD CONSTRAINT mcp_agents_name_key UNIQUE (name);


--
-- Name: mcp_agents mcp_agents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_agents
    ADD CONSTRAINT mcp_agents_pkey PRIMARY KEY (id);


--
-- Name: mcp_crate_allowlist mcp_crate_allowlist_crate_name_org_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_crate_allowlist
    ADD CONSTRAINT mcp_crate_allowlist_crate_name_org_id_key UNIQUE (crate_name, org_id);


--
-- Name: mcp_crate_allowlist mcp_crate_allowlist_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_crate_allowlist
    ADD CONSTRAINT mcp_crate_allowlist_pkey PRIMARY KEY (id);


--
-- Name: module_marketplace module_marketplace_name_version_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.module_marketplace
    ADD CONSTRAINT module_marketplace_name_version_key UNIQUE (name, version);


--
-- Name: module_marketplace module_marketplace_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.module_marketplace
    ADD CONSTRAINT module_marketplace_pkey PRIMARY KEY (id);


--
-- Name: module_marketplace_stars module_marketplace_stars_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.module_marketplace_stars
    ADD CONSTRAINT module_marketplace_stars_pkey PRIMARY KEY (user_id, listing_id);


--
-- Name: module_update_history module_update_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.module_update_history
    ADD CONSTRAINT module_update_history_pkey PRIMARY KEY (id);


--
-- Name: modules modules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.modules
    ADD CONSTRAINT modules_pkey PRIMARY KEY (id);


--
-- Name: module_execution_logs node_execution_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.module_execution_logs
    ADD CONSTRAINT node_execution_logs_pkey PRIMARY KEY (id);


--
-- Name: module_executions node_executions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.module_executions
    ADD CONSTRAINT node_executions_pkey PRIMARY KEY (id);


--
-- Name: node_result_cache node_result_cache_cache_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_result_cache
    ADD CONSTRAINT node_result_cache_cache_key_key UNIQUE (cache_key);


--
-- Name: node_result_cache node_result_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.node_result_cache
    ADD CONSTRAINT node_result_cache_pkey PRIMARY KEY (id);


--
-- Name: oauth_accounts oauth_accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_accounts
    ADD CONSTRAINT oauth_accounts_pkey PRIMARY KEY (id);


--
-- Name: oauth_accounts oauth_accounts_provider_provider_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_accounts
    ADD CONSTRAINT oauth_accounts_provider_provider_user_id_key UNIQUE (provider, provider_user_id);


--
-- Name: oauth_accounts oauth_accounts_user_id_provider_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_accounts
    ADD CONSTRAINT oauth_accounts_user_id_provider_key UNIQUE (user_id, provider);


--
-- Name: oauth_audit_log oauth_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_audit_log
    ADD CONSTRAINT oauth_audit_log_pkey PRIMARY KEY (id);


--
-- Name: oauth_state_tokens oauth_state_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_state_tokens
    ADD CONSTRAINT oauth_state_tokens_pkey PRIMARY KEY (id);


--
-- Name: oauth_state_tokens oauth_state_tokens_state_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_state_tokens
    ADD CONSTRAINT oauth_state_tokens_state_token_key UNIQUE (state_token);


--
-- Name: organization_members organization_members_org_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_members
    ADD CONSTRAINT organization_members_org_id_user_id_key UNIQUE (org_id, user_id);


--
-- Name: organization_members organization_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_members
    ADD CONSTRAINT organization_members_pkey PRIMARY KEY (id);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);


--
-- Name: organizations organizations_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_slug_key UNIQUE (slug);


--
-- Name: resource_quotas resource_quotas_org_id_metric_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_quotas
    ADD CONSTRAINT resource_quotas_org_id_metric_key UNIQUE (org_id, metric);


--
-- Name: resource_quotas resource_quotas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_quotas
    ADD CONSTRAINT resource_quotas_pkey PRIMARY KEY (id);


--
-- Name: rotated_session_audit rotated_session_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rotated_session_audit
    ADD CONSTRAINT rotated_session_audit_pkey PRIMARY KEY (lookup_hash);


--
-- Name: schema_audit_log schema_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_audit_log
    ADD CONSTRAINT schema_audit_log_pkey PRIMARY KEY (id);


--
-- Name: scratch_sessions scratch_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scratch_sessions
    ADD CONSTRAINT scratch_sessions_pkey PRIMARY KEY (id);


--
-- Name: scratch_sessions scratch_sessions_user_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scratch_sessions
    ADD CONSTRAINT scratch_sessions_user_id_name_key UNIQUE (user_id, name);


--
-- Name: secret_audit_log secret_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_audit_log
    ADD CONSTRAINT secret_audit_log_pkey PRIMARY KEY (id);


--
-- Name: secrets secrets_namespace_key_path_user_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT secrets_namespace_key_path_user_unique UNIQUE (namespace, key_path, created_by);


--
-- Name: secrets secrets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT secrets_pkey PRIMARY KEY (id);


--
-- Name: secrets_rotation_log secrets_rotation_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secrets_rotation_log
    ADD CONSTRAINT secrets_rotation_log_pkey PRIMARY KEY (id);


--
-- Name: semantic_execution_cache semantic_execution_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.semantic_execution_cache
    ADD CONSTRAINT semantic_execution_cache_pkey PRIMARY KEY (id);


--
-- Name: slack_integration_audit_log slack_integration_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.slack_integration_audit_log
    ADD CONSTRAINT slack_integration_audit_log_pkey PRIMARY KEY (id);


--
-- Name: slack_integrations slack_integrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.slack_integrations
    ADD CONSTRAINT slack_integrations_pkey PRIMARY KEY (id);


--
-- Name: slack_integrations slack_integrations_user_id_team_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.slack_integrations
    ADD CONSTRAINT slack_integrations_user_id_team_id_key UNIQUE (user_id, team_id);


--
-- Name: system_settings system_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_settings
    ADD CONSTRAINT system_settings_pkey PRIMARY KEY (key);


--
-- Name: tenant_quotas tenant_quotas_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_quotas
    ADD CONSTRAINT tenant_quotas_pkey PRIMARY KEY (id);


--
-- Name: user_audit_settings user_audit_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_audit_settings
    ADD CONSTRAINT user_audit_settings_pkey PRIMARY KEY (user_id);


--
-- Name: user_capability_grants user_capability_grants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_capability_grants
    ADD CONSTRAINT user_capability_grants_pkey PRIMARY KEY (id);


--
-- Name: user_capability_grants user_capability_grants_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_capability_grants
    ADD CONSTRAINT user_capability_grants_user_id_key UNIQUE (user_id);


--
-- Name: user_module_pins user_module_pins_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_module_pins
    ADD CONSTRAINT user_module_pins_pkey PRIMARY KEY (user_id, module_name);


--
-- Name: user_sessions user_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_sessions
    ADD CONSTRAINT user_sessions_pkey PRIMARY KEY (id);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: webhook_dlq webhook_dlq_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_dlq
    ADD CONSTRAINT webhook_dlq_pkey PRIMARY KEY (id);


--
-- Name: webhook_triggers webhook_listeners_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_triggers
    ADD CONSTRAINT webhook_listeners_pkey PRIMARY KEY (id);


--
-- Name: webhook_processed_events webhook_processed_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_processed_events
    ADD CONSTRAINT webhook_processed_events_pkey PRIMARY KEY (id);


--
-- Name: webhook_processed_events webhook_processed_events_trigger_id_event_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_processed_events
    ADD CONSTRAINT webhook_processed_events_trigger_id_event_id_key UNIQUE (trigger_id, event_id);


--
-- Name: webhook_request_log webhook_request_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_request_log
    ADD CONSTRAINT webhook_request_log_pkey PRIMARY KEY (id);


--
-- Name: worker_identities worker_identities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.worker_identities
    ADD CONSTRAINT worker_identities_pkey PRIMARY KEY (worker_id, public_key);


--
-- Name: worker_provisioning_tokens worker_provisioning_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.worker_provisioning_tokens
    ADD CONSTRAINT worker_provisioning_tokens_pkey PRIMARY KEY (id);


--
-- Name: worker_provisioning_tokens worker_provisioning_tokens_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.worker_provisioning_tokens
    ADD CONSTRAINT worker_provisioning_tokens_token_hash_key UNIQUE (token_hash);


--
-- Name: workflow_alerts workflow_alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_alerts
    ADD CONSTRAINT workflow_alerts_pkey PRIMARY KEY (id);


--
-- Name: workflow_approval_gates workflow_approval_gates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_approval_gates
    ADD CONSTRAINT workflow_approval_gates_pkey PRIMARY KEY (id);


--
-- Name: workflow_approval_gates workflow_approval_gates_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_approval_gates
    ADD CONSTRAINT workflow_approval_gates_token_key UNIQUE (token);


--
-- Name: workflow_execution_logs workflow_execution_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_execution_logs
    ADD CONSTRAINT workflow_execution_logs_pkey PRIMARY KEY (id);


--
-- Name: workflow_executions_archive workflow_executions_archive_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_executions_archive
    ADD CONSTRAINT workflow_executions_archive_pkey PRIMARY KEY (id);


--
-- Name: workflow_executions workflow_executions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_executions
    ADD CONSTRAINT workflow_executions_pkey PRIMARY KEY (id);


--
-- Name: workflow_module_refs workflow_module_refs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_module_refs
    ADD CONSTRAINT workflow_module_refs_pkey PRIMARY KEY (workflow_id, module_id);


--
-- Name: workflow_nodes workflow_nodes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_nodes
    ADD CONSTRAINT workflow_nodes_pkey PRIMARY KEY (id);


--
-- Name: workflow_reuse_events workflow_reuse_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_reuse_events
    ADD CONSTRAINT workflow_reuse_events_pkey PRIMARY KEY (id);


--
-- Name: workflow_schedules workflow_schedules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_schedules
    ADD CONSTRAINT workflow_schedules_pkey PRIMARY KEY (id);


--
-- Name: workflow_schedules workflow_schedules_workflow_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_schedules
    ADD CONSTRAINT workflow_schedules_workflow_id_key UNIQUE (workflow_id);


--
-- Name: workflow_sla_thresholds workflow_sla_thresholds_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_sla_thresholds
    ADD CONSTRAINT workflow_sla_thresholds_pkey PRIMARY KEY (id);


--
-- Name: workflow_sla_thresholds workflow_sla_thresholds_workflow_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_sla_thresholds
    ADD CONSTRAINT workflow_sla_thresholds_workflow_id_user_id_key UNIQUE (workflow_id, user_id);


--
-- Name: workflow_suspensions workflow_suspensions_correlation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_suspensions
    ADD CONSTRAINT workflow_suspensions_correlation_id_key UNIQUE (correlation_id);


--
-- Name: workflow_suspensions workflow_suspensions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_suspensions
    ADD CONSTRAINT workflow_suspensions_pkey PRIMARY KEY (id);


--
-- Name: workflow_versions workflow_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_versions
    ADD CONSTRAINT workflow_versions_pkey PRIMARY KEY (id);


--
-- Name: workflow_versions workflow_versions_workflow_id_version_number_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_versions
    ADD CONSTRAINT workflow_versions_workflow_id_version_number_key UNIQUE (workflow_id, version_number);


--
-- Name: workflows workflows_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflows
    ADD CONSTRAINT workflows_pkey PRIMARY KEY (id);


--
-- Name: idx_actor_action_log_actor_ts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_actor_action_log_actor_ts ON public.actor_action_log USING btree (actor_id, "timestamp" DESC);


--
-- Name: idx_actor_action_log_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_actor_action_log_org ON public.actor_action_log USING btree (org_id);


--
-- Name: idx_actor_approval_policies_actor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_actor_approval_policies_actor ON public.actor_approval_policies USING btree (actor_id);


--
-- Name: idx_actor_approval_policies_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_actor_approval_policies_org ON public.actor_approval_policies USING btree (org_id);


--
-- Name: idx_actor_budget_policies_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_actor_budget_policies_org ON public.actor_budget_policies USING btree (org_id);


--
-- Name: idx_actor_memory_actor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_actor_memory_actor ON public.actor_memory USING btree (actor_id);


--
-- Name: idx_actor_memory_embedding; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_actor_memory_embedding ON public.actor_memory USING ivfflat (embedding public.vector_cosine_ops) WITH (lists='10');


--
-- Name: idx_actor_memory_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_actor_memory_expires ON public.actor_memory USING btree (expires_at) WHERE (expires_at IS NOT NULL);


--
-- Name: idx_actor_memory_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_actor_memory_org ON public.actor_memory USING btree (org_id);


--
-- Name: idx_actors_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_actors_active ON public.actors USING btree (user_id, status) WHERE (status = 'active'::text);


--
-- Name: idx_actors_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_actors_org ON public.actors USING btree (org_id, user_id);


--
-- Name: idx_actors_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_actors_user_id ON public.actors USING btree (user_id);


--
-- Name: idx_actors_user_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_actors_user_name ON public.actors USING btree (user_id, name);


--
-- Name: idx_admin_event_log_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_admin_event_log_created_at ON public.admin_event_log USING btree (created_at DESC);


--
-- Name: idx_admin_event_log_resource; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_admin_event_log_resource ON public.admin_event_log USING btree (resource_type, resource_id);


--
-- Name: idx_admin_event_log_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_admin_event_log_user_id ON public.admin_event_log USING btree (user_id);


--
-- Name: idx_alerts_user_unacked; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_user_unacked ON public.workflow_alerts USING btree (user_id, acknowledged) WHERE (acknowledged = false);


--
-- Name: idx_api_keys_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_keys_active ON public.api_keys USING btree (is_active) WHERE (is_active = true);


--
-- Name: idx_api_keys_key_prefix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_keys_key_prefix ON public.api_keys USING btree (key_prefix);


--
-- Name: idx_api_keys_key_prefix_active; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_api_keys_key_prefix_active ON public.api_keys USING btree (key_prefix) WHERE (is_active = true);


--
-- Name: idx_api_keys_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_keys_org ON public.api_keys USING btree (org_id, user_id);


--
-- Name: idx_api_keys_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_keys_org_id ON public.api_keys USING btree (org_id) WHERE (org_id IS NOT NULL);


--
-- Name: idx_api_keys_prefix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_keys_prefix ON public.api_keys USING btree (key_prefix);


--
-- Name: idx_api_keys_prefix_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_keys_prefix_active ON public.api_keys USING btree (key_prefix, is_active) WHERE (is_active = true);


--
-- Name: idx_api_keys_user_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_keys_user_active ON public.api_keys USING btree (user_id, is_active) WHERE (is_active = true);


--
-- Name: idx_api_keys_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_keys_user_id ON public.api_keys USING btree (user_id);


--
-- Name: idx_approval_gates_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_approval_gates_expires ON public.workflow_approval_gates USING btree (expires_at) WHERE (status = 'pending'::text);


--
-- Name: idx_approval_gates_token_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_approval_gates_token_hash ON public.workflow_approval_gates USING btree (token_hash);


--
-- Name: idx_approval_gates_user_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_approval_gates_user_status ON public.workflow_approval_gates USING btree (user_id, status, created_at DESC) WHERE (status = 'pending'::text);


--
-- Name: idx_archive_user_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_archive_user_started ON public.workflow_executions_archive USING btree (user_id, started_at DESC);


--
-- Name: idx_atlassian_integrations_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_atlassian_integrations_org ON public.atlassian_integrations USING btree (org_id, user_id);


--
-- Name: idx_atlassian_integrations_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_atlassian_integrations_user ON public.atlassian_integrations USING btree (user_id);


--
-- Name: idx_audit_events_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_events_action ON public.audit_events USING btree (action, "timestamp" DESC);


--
-- Name: idx_audit_events_execution; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_events_execution ON public.audit_events USING btree (execution_id, sequence_num);


--
-- Name: idx_audit_events_workflow; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_events_workflow ON public.audit_events USING btree (workflow_id, "timestamp" DESC);


--
-- Name: idx_auth_audit_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auth_audit_created ON public.auth_audit_log USING btree (created_at DESC);


--
-- Name: idx_auth_audit_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auth_audit_email ON public.auth_audit_log USING btree (email) WHERE (email IS NOT NULL);


--
-- Name: idx_auth_audit_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auth_audit_user_id ON public.auth_audit_log USING btree (user_id);


--
-- Name: idx_circuit_breaker_service; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_circuit_breaker_service ON public.circuit_breaker_metrics USING btree (service_name, recorded_at);


--
-- Name: idx_compilation_cache_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_compilation_cache_created ON public.compilation_cache USING btree (created_at);


--
-- Name: idx_cost_rollup_actor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_cost_rollup_actor ON public.execution_cost_rollup USING btree (actor_id, recorded_at) WHERE (actor_id IS NOT NULL);


--
-- Name: idx_cost_rollup_execution; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_cost_rollup_execution ON public.execution_cost_rollup USING btree (execution_id);


--
-- Name: idx_cost_rollup_workflow; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_cost_rollup_workflow ON public.execution_cost_rollup USING btree (workflow_id, recorded_at);


--
-- Name: idx_dead_letter_jobs_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dead_letter_jobs_org ON public.dead_letter_jobs USING btree (org_id, user_id);


--
-- Name: idx_dead_letter_jobs_original; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dead_letter_jobs_original ON public.dead_letter_jobs USING btree (original_job_id);


--
-- Name: idx_dlq_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dlq_pending ON public.dead_letter_queue USING btree (created_at) WHERE (replayed_at IS NULL);


--
-- Name: idx_encryption_keys_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_encryption_keys_active ON public.encryption_keys USING btree (active) WHERE (active = true);


--
-- Name: idx_events_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_events_created_at ON public.execution_events USING btree (execution_id, created_at);


--
-- Name: idx_events_execution_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_events_execution_id ON public.execution_events USING btree (execution_id);


--
-- Name: idx_exec_cache_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_exec_cache_active ON public.semantic_execution_cache USING btree (workflow_id, created_at DESC) WHERE (expires_at IS NULL);


--
-- Name: idx_exec_cache_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_exec_cache_expires ON public.semantic_execution_cache USING btree (expires_at) WHERE (expires_at IS NOT NULL);


--
-- Name: idx_exec_cache_workflow_embedding; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_exec_cache_workflow_embedding ON public.semantic_execution_cache USING ivfflat (input_embedding public.vector_cosine_ops) WITH (lists='20') WHERE (input_embedding IS NOT NULL);


--
-- Name: idx_exec_cache_workflow_hash_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_exec_cache_workflow_hash_unique ON public.semantic_execution_cache USING btree (workflow_id, input_hash);


--
-- Name: idx_exec_events_node_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_exec_events_node_started ON public.execution_events USING btree (execution_id, node_id, event_type, created_at DESC) WHERE (event_type = 'node_started'::text);


--
-- Name: idx_execution_approvals_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_execution_approvals_lookup ON public.execution_approvals USING btree (execution_id, node_id, status);


--
-- Name: idx_execution_approvals_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_execution_approvals_org ON public.execution_approvals USING btree (org_id);


--
-- Name: idx_execution_approvals_workflow_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_execution_approvals_workflow_pending ON public.execution_approvals USING btree (workflow_id, status) WHERE (status = 'pending'::text);


--
-- Name: idx_execution_cost_rollup_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_execution_cost_rollup_org ON public.execution_cost_rollup USING btree (org_id);


--
-- Name: idx_execution_events_error_class; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_execution_events_error_class ON public.execution_events USING btree (error_class, created_at) WHERE (error_class IS NOT NULL);


--
-- Name: idx_execution_events_exec_node; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_execution_events_exec_node ON public.execution_events USING btree (execution_id, node_id, created_at DESC);


--
-- Name: idx_execution_events_execution_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_execution_events_execution_created ON public.execution_events USING btree (execution_id, created_at);


--
-- Name: idx_execution_events_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_execution_events_org ON public.execution_events USING btree (org_id);


--
-- Name: idx_execution_state_exec; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_execution_state_exec ON public.execution_state USING btree (execution_id);


--
-- Name: idx_execution_state_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_execution_state_lookup ON public.execution_state USING btree (execution_id, key);


--
-- Name: idx_execution_state_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_execution_state_org ON public.execution_state USING btree (org_id);


--
-- Name: idx_executions_acknowledged; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_executions_acknowledged ON public.workflow_executions USING btree (workflow_id, acknowledged_at) WHERE (acknowledged_at IS NOT NULL);


--
-- Name: idx_executions_replayed_from; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_executions_replayed_from ON public.workflow_executions USING btree (replayed_from_id) WHERE (replayed_from_id IS NOT NULL);


--
-- Name: idx_executions_started_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_executions_started_at ON public.workflow_executions USING btree (started_at DESC);


--
-- Name: idx_executions_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_executions_status ON public.workflow_executions USING btree (status);


--
-- Name: idx_executions_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_executions_user_id ON public.workflow_executions USING btree (user_id);


--
-- Name: idx_executions_user_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_executions_user_started ON public.workflow_executions USING btree (user_id, started_at DESC);


--
-- Name: idx_executions_workflow_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_executions_workflow_id ON public.workflow_executions USING btree (workflow_id);


--
-- Name: idx_feature_flags_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_feature_flags_name ON public.feature_flags USING btree (name);


--
-- Name: idx_github_app_installations_account_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_github_app_installations_account_active ON public.github_app_installations USING btree (account_login) WHERE is_active;


--
-- Name: idx_github_app_installations_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_github_app_installations_user_id ON public.github_app_installations USING btree (user_id);


--
-- Name: idx_gmail_integrations_active_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_gmail_integrations_active_email ON public.gmail_integrations USING btree (email_address) WHERE (is_active = true);


--
-- Name: idx_gmail_integrations_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_gmail_integrations_org ON public.gmail_integrations USING btree (org_id, user_id);


--
-- Name: idx_gmail_integrations_user_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_gmail_integrations_user_active ON public.gmail_integrations USING btree (user_id, is_active);


--
-- Name: idx_gmail_integrations_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_gmail_integrations_user_id ON public.gmail_integrations USING btree (user_id);


--
-- Name: idx_google_calendar_audit_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_google_calendar_audit_created_at ON public.google_calendar_audit_log USING btree (created_at DESC);


--
-- Name: idx_google_calendar_audit_integration_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_google_calendar_audit_integration_id ON public.google_calendar_audit_log USING btree (integration_id);


--
-- Name: idx_google_calendar_audit_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_google_calendar_audit_user_id ON public.google_calendar_audit_log USING btree (user_id);


--
-- Name: idx_google_calendar_integrations_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_google_calendar_integrations_active ON public.google_calendar_integrations USING btree (is_active) WHERE (is_active = true);


--
-- Name: idx_google_calendar_integrations_oauth_account; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_google_calendar_integrations_oauth_account ON public.google_calendar_integrations USING btree (oauth_account_id);


--
-- Name: idx_google_calendar_integrations_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_google_calendar_integrations_org ON public.google_calendar_integrations USING btree (org_id, user_id);


--
-- Name: idx_google_calendar_integrations_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_google_calendar_integrations_user_id ON public.google_calendar_integrations USING btree (user_id);


--
-- Name: idx_google_calendar_watch_channels_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_google_calendar_watch_channels_active ON public.google_calendar_watch_channels USING btree (is_active) WHERE (is_active = true);


--
-- Name: idx_google_calendar_watch_channels_calendar_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_google_calendar_watch_channels_calendar_id ON public.google_calendar_watch_channels USING btree (calendar_id);


--
-- Name: idx_google_calendar_watch_channels_expiration; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_google_calendar_watch_channels_expiration ON public.google_calendar_watch_channels USING btree (expiration) WHERE (is_active = true);


--
-- Name: idx_google_calendar_watch_channels_integration_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_google_calendar_watch_channels_integration_id ON public.google_calendar_watch_channels USING btree (integration_id);


--
-- Name: idx_idempotency_keys_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_idempotency_keys_expires ON public.idempotency_keys USING btree (expires_at);


--
-- Name: idx_idempotency_keys_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_idempotency_keys_key ON public.idempotency_keys USING btree (key);


--
-- Name: idx_idempotency_keys_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_idempotency_keys_org ON public.idempotency_keys USING btree (org_id, user_id);


--
-- Name: idx_integration_credentials_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_credentials_org ON public.integration_credentials USING btree (org_id, user_id);


--
-- Name: idx_integration_credentials_provider; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_credentials_provider ON public.integration_credentials USING btree (provider);


--
-- Name: idx_integration_credentials_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_credentials_user_id ON public.integration_credentials USING btree (user_id);


--
-- Name: idx_integration_credentials_user_provider; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_credentials_user_provider ON public.integration_credentials USING btree (user_id, provider, is_active);


--
-- Name: idx_integration_credentials_user_provider_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_credentials_user_provider_active ON public.integration_credentials USING btree (user_id, provider, is_active) WHERE (is_active = true);


--
-- Name: idx_integration_state_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_state_org ON public.integration_state USING btree (org_id, user_id);


--
-- Name: idx_jobs_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_jobs_org ON public.jobs USING btree (org_id, user_id);


--
-- Name: idx_jobs_priority; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_jobs_priority ON public.jobs USING btree (priority DESC);


--
-- Name: idx_jobs_status_scheduled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_jobs_status_scheduled ON public.jobs USING btree (status, scheduled_at);


--
-- Name: idx_jobs_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_jobs_user_id ON public.jobs USING btree (user_id);


--
-- Name: idx_marketplace_downloads; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_marketplace_downloads ON public.module_marketplace USING btree (downloads DESC);


--
-- Name: idx_marketplace_stars; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_marketplace_stars ON public.module_marketplace USING btree (star_count DESC);


--
-- Name: idx_marketplace_stars_listing; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_marketplace_stars_listing ON public.module_marketplace_stars USING btree (listing_id);


--
-- Name: idx_marketplace_tags; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_marketplace_tags ON public.module_marketplace USING gin (tags);


--
-- Name: idx_marketplace_world; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_marketplace_world ON public.module_marketplace USING btree (capability_world);


--
-- Name: idx_mcp_agents_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mcp_agents_org ON public.mcp_agents USING btree (org_id, user_id);


--
-- Name: idx_mcp_agents_role_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mcp_agents_role_id ON public.mcp_agents USING btree (role_id);


--
-- Name: idx_mcp_agents_token_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mcp_agents_token_hash ON public.mcp_agents USING btree (token_hash);


--
-- Name: idx_mcp_agents_token_lookup_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mcp_agents_token_lookup_hash ON public.mcp_agents USING btree (token_lookup_hash) WHERE (token_lookup_hash IS NOT NULL);


--
-- Name: idx_mcp_agents_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mcp_agents_user_id ON public.mcp_agents USING btree (user_id);


--
-- Name: idx_mcp_crate_allowlist_global; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mcp_crate_allowlist_global ON public.mcp_crate_allowlist USING btree (is_global) WHERE (is_global = true);


--
-- Name: idx_mcp_crate_allowlist_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mcp_crate_allowlist_org ON public.mcp_crate_allowlist USING btree (org_id);


--
-- Name: idx_module_execution_logs_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_execution_logs_created_at ON public.module_execution_logs USING btree (execution_id, created_at);


--
-- Name: idx_module_execution_logs_execution_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_execution_logs_execution_id ON public.module_execution_logs USING btree (execution_id);


--
-- Name: idx_module_execution_logs_level; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_execution_logs_level ON public.module_execution_logs USING btree (execution_id, level);


--
-- Name: idx_module_executions_actor_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_executions_actor_id ON public.module_executions USING btree (actor_id) WHERE (actor_id IS NOT NULL);


--
-- Name: idx_module_executions_log_count; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_executions_log_count ON public.module_executions USING btree (log_count);


--
-- Name: idx_module_executions_module_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_executions_module_created ON public.module_executions USING btree (module_id, started_at DESC);


--
-- Name: idx_module_executions_module_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_executions_module_id ON public.module_executions USING btree (module_id);


--
-- Name: idx_module_executions_module_recent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_executions_module_recent ON public.module_executions USING btree (module_id, started_at DESC);


--
-- Name: idx_module_executions_needs_payload_encryption; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_executions_needs_payload_encryption ON public.module_executions USING btree (id) WHERE ((payload_enc_key_id IS NULL) AND ((input_data IS NOT NULL) OR (output_data IS NOT NULL) OR (trigger_metadata IS NOT NULL)));


--
-- Name: idx_module_executions_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_executions_org ON public.module_executions USING btree (org_id, user_id);


--
-- Name: idx_module_executions_started_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_executions_started_at ON public.module_executions USING btree (started_at DESC);


--
-- Name: idx_module_executions_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_executions_status ON public.module_executions USING btree (status);


--
-- Name: idx_module_executions_status_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_executions_status_created ON public.module_executions USING btree (status, created_at DESC);


--
-- Name: idx_module_executions_stuck; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_executions_stuck ON public.module_executions USING btree (status, started_at) WHERE (status = ANY (ARRAY['pending'::text, 'running'::text]));


--
-- Name: idx_module_executions_trigger; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_executions_trigger ON public.module_executions USING btree (trigger_type, started_at DESC);


--
-- Name: idx_module_executions_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_executions_user_id ON public.module_executions USING btree (user_id);


--
-- Name: idx_module_executions_user_module_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_executions_user_module_started ON public.module_executions USING btree (user_id, module_id, started_at DESC);


--
-- Name: idx_module_executions_user_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_executions_user_started ON public.module_executions USING btree (user_id, started_at DESC);


--
-- Name: idx_module_executions_user_status_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_executions_user_status_created ON public.module_executions USING btree (user_id, status, created_at DESC);


--
-- Name: idx_module_executions_wf_exec_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_executions_wf_exec_status ON public.module_executions USING btree (workflow_execution_id, status) WHERE (workflow_execution_id IS NOT NULL);


--
-- Name: idx_module_executions_workflow_exec; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_executions_workflow_exec ON public.module_executions USING btree (workflow_execution_id) WHERE (workflow_execution_id IS NOT NULL);


--
-- Name: idx_module_history_module; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_history_module ON public.module_update_history USING btree (module_id, created_at DESC);


--
-- Name: idx_module_marketplace_stars_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_marketplace_stars_org ON public.module_marketplace_stars USING btree (org_id, user_id);


--
-- Name: idx_module_update_history_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_module_update_history_org ON public.module_update_history USING btree (org_id, user_id);


--
-- Name: idx_modules_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_modules_org ON public.modules USING btree (org_id, user_id);


--
-- Name: idx_node_result_cache_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_node_result_cache_expires ON public.node_result_cache USING btree (expires_at);


--
-- Name: idx_node_result_cache_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_node_result_cache_key ON public.node_result_cache USING btree (cache_key);


--
-- Name: idx_oauth_accounts_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_accounts_email ON public.oauth_accounts USING btree (email);


--
-- Name: idx_oauth_accounts_provider_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_accounts_provider_active ON public.oauth_accounts USING btree (provider, user_id);


--
-- Name: idx_oauth_accounts_provider_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_accounts_provider_user ON public.oauth_accounts USING btree (provider, provider_user_id);


--
-- Name: idx_oauth_accounts_provider_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_accounts_provider_user_id ON public.oauth_accounts USING btree (provider, provider_user_id);


--
-- Name: idx_oauth_accounts_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_accounts_user_id ON public.oauth_accounts USING btree (user_id);


--
-- Name: idx_oauth_audit_log_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_audit_log_created_at ON public.oauth_audit_log USING btree (created_at DESC);


--
-- Name: idx_oauth_audit_log_provider; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_audit_log_provider ON public.oauth_audit_log USING btree (provider);


--
-- Name: idx_oauth_audit_log_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_audit_log_user_id ON public.oauth_audit_log USING btree (user_id);


--
-- Name: idx_oauth_state_tokens_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_state_tokens_expires ON public.oauth_state_tokens USING btree (expires_at);


--
-- Name: idx_oauth_state_tokens_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_state_tokens_state ON public.oauth_state_tokens USING btree (state_token);


--
-- Name: idx_oauth_state_tokens_state_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_state_tokens_state_expires ON public.oauth_state_tokens USING btree (state_token, expires_at);


--
-- Name: idx_one_active_dek_per_org; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_one_active_dek_per_org ON public.encryption_keys USING btree (org_id) WHERE (active AND (org_id IS NOT NULL));


--
-- Name: idx_one_active_global_dek; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_one_active_global_dek ON public.encryption_keys USING btree (active) WHERE (active AND (org_id IS NULL));


--
-- Name: idx_one_default_actor_per_user; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_one_default_actor_per_user ON public.actors USING btree (user_id) WHERE is_default;


--
-- Name: idx_one_personal_org_per_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_one_personal_org_per_owner ON public.organizations USING btree (owner_id) WHERE is_personal;


--
-- Name: idx_org_members_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_org_members_org ON public.organization_members USING btree (org_id);


--
-- Name: idx_org_members_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_org_members_user ON public.organization_members USING btree (user_id);


--
-- Name: idx_resource_quotas_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_resource_quotas_org ON public.resource_quotas USING btree (org_id);


--
-- Name: idx_reuse_events_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reuse_events_created ON public.workflow_reuse_events USING btree (created_at DESC);


--
-- Name: idx_reuse_events_workflow; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reuse_events_workflow ON public.workflow_reuse_events USING btree (workflow_id, created_at DESC);


--
-- Name: idx_scratch_sessions_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scratch_sessions_org ON public.scratch_sessions USING btree (org_id, user_id);


--
-- Name: idx_scratch_sessions_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_scratch_sessions_user_id ON public.scratch_sessions USING btree (user_id);


--
-- Name: idx_secret_audit_log_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secret_audit_log_org ON public.secret_audit_log USING btree (org_id);


--
-- Name: idx_secret_audit_secret_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secret_audit_secret_id ON public.secret_audit_log USING btree (secret_id);


--
-- Name: idx_secret_audit_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secret_audit_timestamp ON public.secret_audit_log USING btree ("timestamp" DESC);


--
-- Name: idx_secrets_created_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secrets_created_by ON public.secrets USING btree (created_by);


--
-- Name: idx_secrets_key_path; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secrets_key_path ON public.secrets USING btree (key_path);


--
-- Name: idx_secrets_key_version; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secrets_key_version ON public.secrets USING btree (key_version);


--
-- Name: idx_secrets_last_accessed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secrets_last_accessed ON public.secrets USING btree (last_accessed_at DESC NULLS LAST);


--
-- Name: idx_secrets_name_namespace_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secrets_name_namespace_user ON public.secrets USING btree (name, namespace, created_by);


--
-- Name: idx_secrets_namespace_keypath; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secrets_namespace_keypath ON public.secrets USING btree (namespace, key_path);


--
-- Name: idx_secrets_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secrets_org ON public.secrets USING btree (org_id, user_id);


--
-- Name: idx_secrets_rotation_key_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secrets_rotation_key_type ON public.secrets_rotation_log USING btree (key_type, rotated_at);


--
-- Name: idx_secrets_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secrets_user_id ON public.secrets USING btree (user_id);


--
-- Name: idx_secrets_user_keypath; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secrets_user_keypath ON public.secrets USING btree (user_id, key_path);


--
-- Name: idx_secrets_user_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_secrets_user_name ON public.secrets USING btree (user_id, name);


--
-- Name: idx_semantic_cache_embedding; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_semantic_cache_embedding ON public.semantic_execution_cache USING ivfflat (input_embedding public.vector_cosine_ops) WITH (lists='10');


--
-- Name: idx_semantic_execution_cache_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_semantic_execution_cache_org ON public.semantic_execution_cache USING btree (org_id);


--
-- Name: idx_sla_thresholds_workflow; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sla_thresholds_workflow ON public.workflow_sla_thresholds USING btree (workflow_id);


--
-- Name: idx_slack_audit_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_slack_audit_created_at ON public.slack_integration_audit_log USING btree (created_at DESC);


--
-- Name: idx_slack_audit_integration_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_slack_audit_integration_id ON public.slack_integration_audit_log USING btree (integration_id);


--
-- Name: idx_slack_audit_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_slack_audit_user_id ON public.slack_integration_audit_log USING btree (user_id);


--
-- Name: idx_slack_integrations_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_slack_integrations_active ON public.slack_integrations USING btree (is_active) WHERE (is_active = true);


--
-- Name: idx_slack_integrations_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_slack_integrations_org ON public.slack_integrations USING btree (org_id, user_id);


--
-- Name: idx_slack_integrations_team_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_slack_integrations_team_id ON public.slack_integrations USING btree (team_id);


--
-- Name: idx_slack_integrations_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_slack_integrations_user_id ON public.slack_integrations USING btree (user_id);


--
-- Name: idx_suspensions_timeout; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_suspensions_timeout ON public.workflow_suspensions USING btree (timeout_at) WHERE ((status = 'waiting'::text) AND (timeout_at IS NOT NULL));


--
-- Name: idx_suspensions_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_suspensions_user ON public.workflow_suspensions USING btree (user_id, status, created_at DESC);


--
-- Name: idx_suspensions_waiting; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_suspensions_waiting ON public.workflow_suspensions USING btree (correlation_id) WHERE (status = 'waiting'::text);


--
-- Name: idx_tenant_quotas_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_tenant_quotas_tenant ON public.tenant_quotas USING btree (tenant_id);


--
-- Name: idx_ucg_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ucg_user ON public.user_capability_grants USING btree (user_id);


--
-- Name: idx_user_module_pins_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_module_pins_org ON public.user_module_pins USING btree (org_id, user_id);


--
-- Name: idx_user_module_pins_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_module_pins_user_id ON public.user_module_pins USING btree (user_id);


--
-- Name: idx_user_sessions_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_sessions_expires_at ON public.user_sessions USING btree (expires_at);


--
-- Name: idx_user_sessions_last_used; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_sessions_last_used ON public.user_sessions USING btree (last_used_at DESC);


--
-- Name: idx_user_sessions_lookup_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_sessions_lookup_hash ON public.user_sessions USING btree (refresh_token_lookup_hash) WHERE (refresh_token_lookup_hash IS NOT NULL);


--
-- Name: idx_user_sessions_user_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_sessions_user_expires ON public.user_sessions USING btree (user_id, expires_at);


--
-- Name: idx_user_sessions_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_sessions_user_id ON public.user_sessions USING btree (user_id);


--
-- Name: idx_user_sessions_user_id_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_sessions_user_id_expires_at ON public.user_sessions USING btree (user_id, expires_at);


--
-- Name: idx_users_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_email ON public.users USING btree (email);


--
-- Name: idx_users_email_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_email_active ON public.users USING btree (email, is_active);


--
-- Name: idx_users_is_platform_admin; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_is_platform_admin ON public.users USING btree (id) WHERE (is_platform_admin = true);


--
-- Name: idx_users_last_login; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_last_login ON public.users USING btree (last_login_at DESC);


--
-- Name: idx_users_locked_until; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_locked_until ON public.users USING btree (locked_until) WHERE (locked_until IS NOT NULL);


--
-- Name: idx_watch_channels_active_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_watch_channels_active_unique ON public.google_calendar_watch_channels USING btree (integration_id, calendar_id) WHERE (is_active = true);


--
-- Name: idx_watch_channels_channel_id_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_watch_channels_channel_id_active ON public.google_calendar_watch_channels USING btree (channel_id, is_active) WHERE (is_active = true);


--
-- Name: idx_watch_channels_module_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_watch_channels_module_id ON public.google_calendar_watch_channels USING btree (module_id) WHERE (is_active = true);


--
-- Name: idx_we_workflow_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_we_workflow_started ON public.workflow_executions USING btree (workflow_id, started_at DESC);


--
-- Name: idx_webhook_dlq_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_dlq_pending ON public.webhook_dlq USING btree (created_at) WHERE (replayed_at IS NULL);


--
-- Name: idx_webhook_dlq_trigger; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_dlq_trigger ON public.webhook_dlq USING btree (trigger_id, created_at DESC);


--
-- Name: idx_webhook_events_trigger; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_events_trigger ON public.webhook_processed_events USING btree (trigger_id, event_id);


--
-- Name: idx_webhook_processed_events_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_processed_events_org ON public.webhook_processed_events USING btree (org_id);


--
-- Name: idx_webhook_request_log_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_request_log_created_at ON public.webhook_request_log USING btree (created_at DESC);


--
-- Name: idx_webhook_request_log_listener_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_request_log_listener_id ON public.webhook_request_log USING btree (trigger_id);


--
-- Name: idx_webhook_request_log_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_request_log_org ON public.webhook_request_log USING btree (org_id);


--
-- Name: idx_webhook_request_log_user_trigger; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_request_log_user_trigger ON public.webhook_request_log USING btree (trigger_id, created_at DESC);


--
-- Name: idx_webhook_triggers_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_triggers_enabled ON public.webhook_triggers USING btree (enabled) WHERE (enabled = true);


--
-- Name: idx_webhook_triggers_enabled_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_triggers_enabled_user ON public.webhook_triggers USING btree (id, enabled, user_id) WHERE (enabled = true);


--
-- Name: idx_webhook_triggers_last_triggered; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_triggers_last_triggered ON public.webhook_triggers USING btree (last_triggered_at DESC NULLS LAST);


--
-- Name: idx_webhook_triggers_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_triggers_lookup ON public.webhook_triggers USING btree (id) WHERE (enabled = true);


--
-- Name: idx_webhook_triggers_module_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_triggers_module_id ON public.webhook_triggers USING btree (module_id);


--
-- Name: idx_webhook_triggers_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_triggers_org ON public.webhook_triggers USING btree (org_id, user_id);


--
-- Name: idx_webhook_triggers_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_triggers_user_id ON public.webhook_triggers USING btree (user_id);


--
-- Name: idx_webhook_triggers_workflow_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_triggers_workflow_id ON public.webhook_triggers USING btree (workflow_id);


--
-- Name: idx_wf_exec_enc_key_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_wf_exec_enc_key_id ON public.workflow_executions USING btree (output_enc_key_id) WHERE (output_enc_key_id IS NOT NULL);


--
-- Name: idx_wf_exec_encrypted_output; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_wf_exec_encrypted_output ON public.workflow_executions USING btree (id) WHERE (output_data_enc IS NOT NULL);


--
-- Name: idx_wf_exec_unencrypted_output; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_wf_exec_unencrypted_output ON public.workflow_executions USING btree (id) WHERE ((output_data IS NOT NULL) AND (output_data_enc IS NULL));


--
-- Name: idx_wf_executions_actor_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_wf_executions_actor_id ON public.workflow_executions USING btree (actor_id) WHERE (actor_id IS NOT NULL);


--
-- Name: idx_wmr_module_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_wmr_module_id ON public.workflow_module_refs USING btree (module_id);


--
-- Name: idx_worker_identities_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_worker_identities_active ON public.worker_identities USING btree (worker_id) WHERE active;


--
-- Name: idx_workflow_alerts_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_alerts_org ON public.workflow_alerts USING btree (org_id, user_id);


--
-- Name: idx_workflow_approval_gates_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_approval_gates_org ON public.workflow_approval_gates USING btree (org_id, user_id);


--
-- Name: idx_workflow_execution_logs_exec; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_execution_logs_exec ON public.workflow_execution_logs USING btree (execution_id);


--
-- Name: idx_workflow_execution_logs_exec_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_execution_logs_exec_created ON public.workflow_execution_logs USING btree (execution_id, created_at);


--
-- Name: idx_workflow_execution_logs_exec_level; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_execution_logs_exec_level ON public.workflow_execution_logs USING btree (execution_id, level);


--
-- Name: idx_workflow_execution_logs_node; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_execution_logs_node ON public.workflow_execution_logs USING btree (execution_id, node_id) WHERE (node_id IS NOT NULL);


--
-- Name: idx_workflow_executions_archive_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_executions_archive_org ON public.workflow_executions_archive USING btree (org_id, user_id);


--
-- Name: idx_workflow_executions_created_desc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_executions_created_desc ON public.workflow_executions USING btree (created_at DESC);


--
-- Name: idx_workflow_executions_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_executions_org ON public.workflow_executions USING btree (org_id, user_id);


--
-- Name: idx_workflow_executions_parent_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_executions_parent_id ON public.workflow_executions USING btree (parent_execution_id) WHERE (parent_execution_id IS NOT NULL);


--
-- Name: idx_workflow_executions_pinned; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_executions_pinned ON public.workflow_executions USING btree (user_id, is_pinned) WHERE (is_pinned = true);


--
-- Name: idx_workflow_executions_root_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_executions_root_id ON public.workflow_executions USING btree (root_execution_id) WHERE (root_execution_id IS NOT NULL);


--
-- Name: idx_workflow_executions_status_updated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_executions_status_updated ON public.workflow_executions USING btree (status, updated_at);


--
-- Name: idx_workflow_executions_stuck; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_executions_stuck ON public.workflow_executions USING btree (status, updated_at) WHERE (status = ANY (ARRAY['pending'::text, 'running'::text]));


--
-- Name: idx_workflow_executions_test; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_executions_test ON public.workflow_executions USING btree (is_test_execution) WHERE (is_test_execution = true);


--
-- Name: idx_workflow_executions_user_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_executions_user_created ON public.workflow_executions USING btree (user_id, created_at DESC);


--
-- Name: idx_workflow_executions_user_status_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_executions_user_status_created ON public.workflow_executions USING btree (user_id, status, created_at DESC);


--
-- Name: idx_workflow_executions_workflow_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_executions_workflow_created ON public.workflow_executions USING btree (workflow_id, created_at DESC);


--
-- Name: idx_workflow_executions_workflow_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_executions_workflow_user ON public.workflow_executions USING btree (workflow_id, user_id);


--
-- Name: idx_workflow_module_refs_module_id_workflow_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_module_refs_module_id_workflow_id ON public.workflow_module_refs USING btree (module_id, workflow_id);


--
-- Name: idx_workflow_module_refs_workflow_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_module_refs_workflow_id ON public.workflow_module_refs USING btree (workflow_id);


--
-- Name: idx_workflow_nodes_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_nodes_org ON public.workflow_nodes USING btree (org_id);


--
-- Name: idx_workflow_nodes_workflow; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_nodes_workflow ON public.workflow_nodes USING btree (workflow_id);


--
-- Name: idx_workflow_schedules_enabled_trigger; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_schedules_enabled_trigger ON public.workflow_schedules USING btree (next_trigger_at) WHERE (is_enabled = true);


--
-- Name: idx_workflow_schedules_next_trigger; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_schedules_next_trigger ON public.workflow_schedules USING btree (next_trigger_at) WHERE (is_enabled = true);


--
-- Name: idx_workflow_schedules_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_schedules_org ON public.workflow_schedules USING btree (org_id, user_id);


--
-- Name: idx_workflow_schedules_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_schedules_user ON public.workflow_schedules USING btree (user_id);


--
-- Name: idx_workflow_sla_thresholds_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_sla_thresholds_org ON public.workflow_sla_thresholds USING btree (org_id, user_id);


--
-- Name: idx_workflow_suspensions_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_suspensions_org ON public.workflow_suspensions USING btree (org_id, user_id);


--
-- Name: idx_workflow_versions_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_versions_active ON public.workflow_versions USING btree (workflow_id) WHERE (is_active = true);


--
-- Name: idx_workflow_versions_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_versions_org ON public.workflow_versions USING btree (org_id);


--
-- Name: idx_workflow_versions_workflow; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflow_versions_workflow ON public.workflow_versions USING btree (workflow_id, version_number DESC);


--
-- Name: idx_workflows_actor_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflows_actor_id ON public.workflows USING btree (actor_id) WHERE (actor_id IS NOT NULL);


--
-- Name: idx_workflows_capabilities; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflows_capabilities ON public.workflows USING gin (capabilities);


--
-- Name: idx_workflows_embedding; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflows_embedding ON public.workflows USING ivfflat (embedding public.vector_cosine_ops) WITH (lists='20');


--
-- Name: idx_workflows_graph_json_trgm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflows_graph_json_trgm ON public.workflows USING gin (graph_json public.gin_trgm_ops);


--
-- Name: idx_workflows_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflows_name ON public.workflows USING btree (name);


--
-- Name: idx_workflows_org; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflows_org ON public.workflows USING btree (org_id) WHERE (org_id IS NOT NULL);


--
-- Name: idx_workflows_search_text_trgm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflows_search_text_trgm ON public.workflows USING gin (search_text public.gin_trgm_ops);


--
-- Name: idx_workflows_tags; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflows_tags ON public.workflows USING gin (tags);


--
-- Name: idx_workflows_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflows_type ON public.workflows USING btree (user_id, workflow_type);


--
-- Name: idx_workflows_user_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflows_user_created ON public.workflows USING btree (user_id, created_at DESC);


--
-- Name: idx_workflows_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflows_user_id ON public.workflows USING btree (user_id);


--
-- Name: idx_workflows_user_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_workflows_user_status ON public.workflows USING btree (user_id, status);


--
-- Name: integration_state_expires_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX integration_state_expires_idx ON public.integration_state USING btree (expires_at) WHERE (expires_at IS NOT NULL);


--
-- Name: integration_state_int1_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX integration_state_int1_idx ON public.integration_state USING btree (integration_name, idx_int_1) WHERE (idx_int_1 IS NOT NULL);


--
-- Name: integration_state_str1_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX integration_state_str1_idx ON public.integration_state USING btree (integration_name, idx_str_1) WHERE (idx_str_1 IS NOT NULL);


--
-- Name: integration_state_str2_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX integration_state_str2_idx ON public.integration_state USING btree (integration_name, idx_str_2) WHERE (idx_str_2 IS NOT NULL);


--
-- Name: integration_state_ts1_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX integration_state_ts1_idx ON public.integration_state USING btree (integration_name, idx_ts_1) WHERE (idx_ts_1 IS NOT NULL);


--
-- Name: integration_state_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX integration_state_user_idx ON public.integration_state USING btree (user_id, integration_name);


--
-- Name: modules_catalog_name_uniq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX modules_catalog_name_uniq ON public.modules USING btree (name) WHERE (user_id IS NULL);


--
-- Name: modules_category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX modules_category ON public.modules USING btree (category) WHERE (category IS NOT NULL);


--
-- Name: modules_content_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX modules_content_hash ON public.modules USING btree (content_hash) WHERE (content_hash IS NOT NULL);


--
-- Name: modules_kind; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX modules_kind ON public.modules USING btree (kind);


--
-- Name: modules_org_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX modules_org_id ON public.modules USING btree (org_id) WHERE (org_id IS NOT NULL);


--
-- Name: modules_user_kind_updated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX modules_user_kind_updated ON public.modules USING btree (user_id, kind, updated_at DESC);


--
-- Name: modules_user_name_uniq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX modules_user_name_uniq ON public.modules USING btree (user_id, name) WHERE (user_id IS NOT NULL);


--
-- Name: rotated_session_audit_expires_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX rotated_session_audit_expires_at_idx ON public.rotated_session_audit USING btree (expires_at);


--
-- Name: rotated_session_audit_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX rotated_session_audit_user_id_idx ON public.rotated_session_audit USING btree (user_id);


--
-- Name: unique_alert_workflow_message; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX unique_alert_workflow_message ON public.workflow_alerts USING btree (workflow_id, message) WHERE (acknowledged = false);


--
-- Name: workflow_executions_archive_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX workflow_executions_archive_created_at_idx ON public.workflow_executions_archive USING btree (created_at DESC);


--
-- Name: workflow_executions_archive_is_test_execution_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX workflow_executions_archive_is_test_execution_idx ON public.workflow_executions_archive USING btree (is_test_execution) WHERE (is_test_execution = true);


--
-- Name: workflow_executions_archive_started_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX workflow_executions_archive_started_at_idx ON public.workflow_executions_archive USING btree (started_at DESC);


--
-- Name: workflow_executions_archive_status_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX workflow_executions_archive_status_idx ON public.workflow_executions_archive USING btree (status);


--
-- Name: workflow_executions_archive_status_updated_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX workflow_executions_archive_status_updated_at_idx ON public.workflow_executions_archive USING btree (status, updated_at);


--
-- Name: workflow_executions_archive_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX workflow_executions_archive_user_id_idx ON public.workflow_executions_archive USING btree (user_id);


--
-- Name: workflow_executions_archive_user_id_is_pinned_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX workflow_executions_archive_user_id_is_pinned_idx ON public.workflow_executions_archive USING btree (user_id, is_pinned) WHERE (is_pinned = true);


--
-- Name: workflow_executions_archive_user_id_started_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX workflow_executions_archive_user_id_started_at_idx ON public.workflow_executions_archive USING btree (user_id, started_at DESC);


--
-- Name: workflow_executions_archive_user_id_status_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX workflow_executions_archive_user_id_status_created_at_idx ON public.workflow_executions_archive USING btree (user_id, status, created_at DESC);


--
-- Name: workflow_executions_archive_workflow_id_created_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX workflow_executions_archive_workflow_id_created_at_idx ON public.workflow_executions_archive USING btree (workflow_id, created_at DESC);


--
-- Name: workflow_executions_archive_workflow_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX workflow_executions_archive_workflow_id_idx ON public.workflow_executions_archive USING btree (workflow_id);


--
-- Name: workflow_executions_archive_workflow_id_started_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX workflow_executions_archive_workflow_id_started_at_idx ON public.workflow_executions_archive USING btree (workflow_id, started_at DESC);


--
-- Name: workflow_executions_archive_workflow_id_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX workflow_executions_archive_workflow_id_user_id_idx ON public.workflow_executions_archive USING btree (workflow_id, user_id);


--
-- Name: google_calendar_integrations google_calendar_integrations_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER google_calendar_integrations_updated_at BEFORE UPDATE ON public.google_calendar_integrations FOR EACH ROW EXECUTE FUNCTION public.update_google_calendar_integrations_updated_at();


--
-- Name: google_calendar_watch_channels google_calendar_watch_channels_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER google_calendar_watch_channels_updated_at BEFORE UPDATE ON public.google_calendar_watch_channels FOR EACH ROW EXECUTE FUNCTION public.update_google_calendar_watch_channels_updated_at();


--
-- Name: integration_state integration_state_touch_updated_at_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER integration_state_touch_updated_at_trigger BEFORE UPDATE ON public.integration_state FOR EACH ROW EXECUTE FUNCTION public.integration_state_touch_updated_at();


--
-- Name: module_execution_logs log_count_enforce_limit; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER log_count_enforce_limit BEFORE INSERT ON public.module_execution_logs FOR EACH ROW EXECUTE FUNCTION public.increment_and_check_module_log_count();


--
-- Name: modules modules_set_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER modules_set_updated_at BEFORE UPDATE ON public.modules FOR EACH ROW EXECUTE FUNCTION public.modules_touch_updated_at();


--
-- Name: slack_integrations slack_integrations_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER slack_integrations_updated_at BEFORE UPDATE ON public.slack_integrations FOR EACH ROW EXECUTE FUNCTION public.update_slack_integrations_updated_at();


--
-- Name: admin_event_log trg_admin_event_log_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_admin_event_log_immutable BEFORE DELETE OR UPDATE ON public.admin_event_log FOR EACH ROW EXECUTE FUNCTION public.prevent_audit_modification();


--
-- Name: audit_events trg_audit_events_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_audit_events_immutable BEFORE DELETE OR UPDATE ON public.audit_events FOR EACH ROW EXECUTE FUNCTION public.prevent_audit_modification();


--
-- Name: auth_audit_log trg_auth_audit_log_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_auth_audit_log_immutable BEFORE DELETE OR UPDATE ON public.auth_audit_log FOR EACH ROW EXECUTE FUNCTION public.prevent_audit_modification();


--
-- Name: workflow_executions trg_cancel_siblings_on_workflow_fail; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_cancel_siblings_on_workflow_fail AFTER UPDATE OF status ON public.workflow_executions FOR EACH ROW EXECUTE FUNCTION public.cancel_siblings_on_workflow_fail();


--
-- Name: execution_events trg_execution_event_duration; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_execution_event_duration BEFORE INSERT ON public.execution_events FOR EACH ROW EXECUTE FUNCTION public.compute_execution_event_duration();


--
-- Name: secret_audit_log trg_secret_audit_log_immutable; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_secret_audit_log_immutable BEFORE DELETE OR UPDATE ON public.secret_audit_log FOR EACH ROW EXECUTE FUNCTION public.prevent_audit_modification();


--
-- Name: module_executions trg_set_default_actor; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_set_default_actor BEFORE INSERT ON public.module_executions FOR EACH ROW EXECUTE FUNCTION public.set_default_actor_on_execution();


--
-- Name: workflow_executions trg_set_default_actor; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_set_default_actor BEFORE INSERT ON public.workflow_executions FOR EACH ROW EXECUTE FUNCTION public.set_default_actor_on_execution();


--
-- Name: actors trg_set_org_id; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_set_org_id BEFORE INSERT ON public.actors FOR EACH ROW EXECUTE FUNCTION public.set_org_id_from_personal_org();


--
-- Name: modules trg_set_org_id; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_set_org_id BEFORE INSERT ON public.modules FOR EACH ROW EXECUTE FUNCTION public.set_org_id_from_personal_org();


--
-- Name: secrets trg_set_org_id; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_set_org_id BEFORE INSERT ON public.secrets FOR EACH ROW EXECUTE FUNCTION public.set_org_id_from_personal_org();


--
-- Name: webhook_triggers trg_set_org_id; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_set_org_id BEFORE INSERT ON public.webhook_triggers FOR EACH ROW EXECUTE FUNCTION public.set_org_id_from_personal_org();


--
-- Name: module_executions trigger_module_execution_duration; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_module_execution_duration BEFORE UPDATE ON public.module_executions FOR EACH ROW EXECUTE FUNCTION public.calculate_module_execution_duration();


--
-- Name: module_executions trigger_module_execution_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_module_execution_updated_at BEFORE UPDATE ON public.module_executions FOR EACH ROW EXECUTE FUNCTION public.update_module_execution_updated_at();


--
-- Name: workflow_executions trigger_workflow_execution_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trigger_workflow_execution_updated_at BEFORE UPDATE ON public.workflow_executions FOR EACH ROW EXECUTE FUNCTION public.update_workflow_execution_updated_at();


--
-- Name: agent_roles update_agent_roles_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_agent_roles_updated_at BEFORE UPDATE ON public.agent_roles FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: mcp_agents update_mcp_agents_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_mcp_agents_updated_at BEFORE UPDATE ON public.mcp_agents FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: secrets update_secrets_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_secrets_updated_at BEFORE UPDATE ON public.secrets FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: user_audit_settings update_user_audit_settings_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_user_audit_settings_updated_at BEFORE UPDATE ON public.user_audit_settings FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: users update_users_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: webhook_triggers update_webhook_listeners_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_webhook_listeners_updated_at BEFORE UPDATE ON public.webhook_triggers FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: workflows update_workflows_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_workflows_updated_at BEFORE UPDATE ON public.workflows FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: workflow_execution_logs workflow_log_count_enforce_limit; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER workflow_log_count_enforce_limit BEFORE INSERT ON public.workflow_execution_logs FOR EACH ROW EXECUTE FUNCTION public.enforce_workflow_log_limit();


--
-- Name: actor_action_log actor_action_log_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.actor_action_log
    ADD CONSTRAINT actor_action_log_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: actor_approval_policies actor_approval_policies_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.actor_approval_policies
    ADD CONSTRAINT actor_approval_policies_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: actor_budget_policies actor_budget_policies_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.actor_budget_policies
    ADD CONSTRAINT actor_budget_policies_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: actor_memory actor_memory_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.actor_memory
    ADD CONSTRAINT actor_memory_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: actor_memory actor_memory_value_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.actor_memory
    ADD CONSTRAINT actor_memory_value_key_id_fkey FOREIGN KEY (value_key_id) REFERENCES public.encryption_keys(id) ON DELETE RESTRICT;


--
-- Name: actors actors_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.actors
    ADD CONSTRAINT actors_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: actor_action_log agent_action_log_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.actor_action_log
    ADD CONSTRAINT agent_action_log_agent_id_fkey FOREIGN KEY (actor_id) REFERENCES public.actors(id) ON DELETE CASCADE;


--
-- Name: actor_approval_policies agent_approval_policies_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.actor_approval_policies
    ADD CONSTRAINT agent_approval_policies_agent_id_fkey FOREIGN KEY (actor_id) REFERENCES public.actors(id) ON DELETE CASCADE;


--
-- Name: actor_budget_policies agent_budget_policies_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.actor_budget_policies
    ADD CONSTRAINT agent_budget_policies_agent_id_fkey FOREIGN KEY (actor_id) REFERENCES public.actors(id) ON DELETE CASCADE;


--
-- Name: actor_memory agent_runtime_memory_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.actor_memory
    ADD CONSTRAINT agent_runtime_memory_agent_id_fkey FOREIGN KEY (actor_id) REFERENCES public.actors(id) ON DELETE CASCADE;


--
-- Name: actors agents_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.actors
    ADD CONSTRAINT agents_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: api_keys api_keys_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: api_keys api_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: atlassian_integrations atlassian_integrations_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.atlassian_integrations
    ADD CONSTRAINT atlassian_integrations_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: atlassian_integrations atlassian_integrations_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.atlassian_integrations
    ADD CONSTRAINT atlassian_integrations_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: compilation_cache compilation_cache_module_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.compilation_cache
    ADD CONSTRAINT compilation_cache_module_id_fkey FOREIGN KEY (module_id) REFERENCES public.modules(id) ON DELETE CASCADE;


--
-- Name: dead_letter_jobs dead_letter_jobs_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dead_letter_jobs
    ADD CONSTRAINT dead_letter_jobs_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: dead_letter_jobs dead_letter_jobs_original_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dead_letter_jobs
    ADD CONSTRAINT dead_letter_jobs_original_job_id_fkey FOREIGN KEY (original_job_id) REFERENCES public.jobs(id);


--
-- Name: dead_letter_jobs dead_letter_jobs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dead_letter_jobs
    ADD CONSTRAINT dead_letter_jobs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: encryption_keys encryption_keys_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.encryption_keys
    ADD CONSTRAINT encryption_keys_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE RESTRICT;


--
-- Name: execution_approvals execution_approvals_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.execution_approvals
    ADD CONSTRAINT execution_approvals_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: execution_cost_rollup execution_cost_rollup_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.execution_cost_rollup
    ADD CONSTRAINT execution_cost_rollup_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: execution_events execution_events_execution_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.execution_events
    ADD CONSTRAINT execution_events_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES public.workflow_executions(id) ON DELETE CASCADE;


--
-- Name: execution_events execution_events_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.execution_events
    ADD CONSTRAINT execution_events_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: execution_state execution_state_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.execution_state
    ADD CONSTRAINT execution_state_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: feature_flags feature_flags_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.feature_flags
    ADD CONSTRAINT feature_flags_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id);


--
-- Name: module_executions fk_module_executions_user_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.module_executions
    ADD CONSTRAINT fk_module_executions_user_id FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: organization_members fk_org_members_invited_by; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_members
    ADD CONSTRAINT fk_org_members_invited_by FOREIGN KEY (invited_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: organization_members fk_org_members_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_members
    ADD CONSTRAINT fk_org_members_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: organizations fk_organizations_owner; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT fk_organizations_owner FOREIGN KEY (owner_id) REFERENCES public.users(id) ON DELETE RESTRICT;


--
-- Name: secrets fk_secrets_created_by; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT fk_secrets_created_by FOREIGN KEY (created_by) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: secrets fk_secrets_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT fk_secrets_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: webhook_triggers fk_webhook_listeners_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_triggers
    ADD CONSTRAINT fk_webhook_listeners_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: workflow_schedules fk_workflow_schedules_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_schedules
    ADD CONSTRAINT fk_workflow_schedules_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: workflow_versions fk_workflow_versions_published_by; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_versions
    ADD CONSTRAINT fk_workflow_versions_published_by FOREIGN KEY (published_by) REFERENCES public.users(id) ON DELETE RESTRICT;


--
-- Name: workflows fk_workflows_user; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflows
    ADD CONSTRAINT fk_workflows_user FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: workflows fk_workflows_user_id; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflows
    ADD CONSTRAINT fk_workflows_user_id FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: github_app_installations github_app_installations_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.github_app_installations
    ADD CONSTRAINT github_app_installations_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: gmail_integrations gmail_integrations_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.gmail_integrations
    ADD CONSTRAINT gmail_integrations_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: gmail_integrations gmail_integrations_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.gmail_integrations
    ADD CONSTRAINT gmail_integrations_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: google_calendar_audit_log google_calendar_audit_log_integration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.google_calendar_audit_log
    ADD CONSTRAINT google_calendar_audit_log_integration_id_fkey FOREIGN KEY (integration_id) REFERENCES public.google_calendar_integrations(id) ON DELETE CASCADE;


--
-- Name: google_calendar_audit_log google_calendar_audit_log_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.google_calendar_audit_log
    ADD CONSTRAINT google_calendar_audit_log_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: google_calendar_integrations google_calendar_integrations_oauth_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.google_calendar_integrations
    ADD CONSTRAINT google_calendar_integrations_oauth_account_id_fkey FOREIGN KEY (oauth_account_id) REFERENCES public.oauth_accounts(id) ON DELETE CASCADE;


--
-- Name: google_calendar_integrations google_calendar_integrations_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.google_calendar_integrations
    ADD CONSTRAINT google_calendar_integrations_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: google_calendar_integrations google_calendar_integrations_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.google_calendar_integrations
    ADD CONSTRAINT google_calendar_integrations_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: google_calendar_watch_channels google_calendar_watch_channels_integration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.google_calendar_watch_channels
    ADD CONSTRAINT google_calendar_watch_channels_integration_id_fkey FOREIGN KEY (integration_id) REFERENCES public.google_calendar_integrations(id) ON DELETE CASCADE;


--
-- Name: google_calendar_watch_channels google_calendar_watch_channels_module_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.google_calendar_watch_channels
    ADD CONSTRAINT google_calendar_watch_channels_module_id_fkey FOREIGN KEY (module_id) REFERENCES public.modules(id) ON DELETE SET NULL;


--
-- Name: idempotency_keys idempotency_keys_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.idempotency_keys
    ADD CONSTRAINT idempotency_keys_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: idempotency_keys idempotency_keys_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.idempotency_keys
    ADD CONSTRAINT idempotency_keys_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: integration_credentials integration_credentials_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_credentials
    ADD CONSTRAINT integration_credentials_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: integration_credentials integration_credentials_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_credentials
    ADD CONSTRAINT integration_credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: integration_state integration_state_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_state
    ADD CONSTRAINT integration_state_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: jobs jobs_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jobs
    ADD CONSTRAINT jobs_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: jobs jobs_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jobs
    ADD CONSTRAINT jobs_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organizations(id);


--
-- Name: jobs jobs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.jobs
    ADD CONSTRAINT jobs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: mcp_agents mcp_agents_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_agents
    ADD CONSTRAINT mcp_agents_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: mcp_agents mcp_agents_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_agents
    ADD CONSTRAINT mcp_agents_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.agent_roles(id) ON DELETE RESTRICT;


--
-- Name: mcp_agents mcp_agents_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_agents
    ADD CONSTRAINT mcp_agents_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: mcp_crate_allowlist mcp_crate_allowlist_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mcp_crate_allowlist
    ADD CONSTRAINT mcp_crate_allowlist_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: module_executions module_executions_actor_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.module_executions
    ADD CONSTRAINT module_executions_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES public.actors(id) ON DELETE RESTRICT;


--
-- Name: module_executions module_executions_module_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.module_executions
    ADD CONSTRAINT module_executions_module_id_fkey FOREIGN KEY (module_id) REFERENCES public.modules(id) ON DELETE CASCADE;


--
-- Name: module_executions module_executions_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.module_executions
    ADD CONSTRAINT module_executions_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: module_executions module_executions_payload_enc_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.module_executions
    ADD CONSTRAINT module_executions_payload_enc_key_id_fkey FOREIGN KEY (payload_enc_key_id) REFERENCES public.encryption_keys(id) ON DELETE RESTRICT;


--
-- Name: module_marketplace_stars module_marketplace_stars_listing_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.module_marketplace_stars
    ADD CONSTRAINT module_marketplace_stars_listing_id_fkey FOREIGN KEY (listing_id) REFERENCES public.module_marketplace(id) ON DELETE CASCADE;


--
-- Name: module_marketplace_stars module_marketplace_stars_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.module_marketplace_stars
    ADD CONSTRAINT module_marketplace_stars_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: module_update_history module_update_history_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.module_update_history
    ADD CONSTRAINT module_update_history_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: modules modules_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.modules
    ADD CONSTRAINT modules_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: module_execution_logs node_execution_logs_execution_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.module_execution_logs
    ADD CONSTRAINT node_execution_logs_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES public.module_executions(id) ON DELETE CASCADE;


--
-- Name: module_executions node_executions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.module_executions
    ADD CONSTRAINT node_executions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: oauth_accounts oauth_accounts_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_accounts
    ADD CONSTRAINT oauth_accounts_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: oauth_audit_log oauth_audit_log_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_audit_log
    ADD CONSTRAINT oauth_audit_log_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: oauth_state_tokens oauth_state_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_state_tokens
    ADD CONSTRAINT oauth_state_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: organization_members organization_members_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization_members
    ADD CONSTRAINT organization_members_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON DELETE CASCADE;


--
-- Name: rotated_session_audit rotated_session_audit_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.rotated_session_audit
    ADD CONSTRAINT rotated_session_audit_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: scratch_sessions scratch_sessions_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scratch_sessions
    ADD CONSTRAINT scratch_sessions_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: secret_audit_log secret_audit_log_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secret_audit_log
    ADD CONSTRAINT secret_audit_log_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: secrets secrets_encryption_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT secrets_encryption_key_id_fkey FOREIGN KEY (encryption_key_id) REFERENCES public.encryption_keys(id);


--
-- Name: secrets secrets_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT secrets_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: secrets secrets_owner_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secrets
    ADD CONSTRAINT secrets_owner_user_id_fkey FOREIGN KEY (owner_user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: secrets_rotation_log secrets_rotation_log_rotated_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.secrets_rotation_log
    ADD CONSTRAINT secrets_rotation_log_rotated_by_fkey FOREIGN KEY (rotated_by) REFERENCES public.users(id);


--
-- Name: semantic_execution_cache semantic_execution_cache_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.semantic_execution_cache
    ADD CONSTRAINT semantic_execution_cache_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: semantic_execution_cache semantic_execution_cache_workflow_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.semantic_execution_cache
    ADD CONSTRAINT semantic_execution_cache_workflow_id_fkey FOREIGN KEY (workflow_id) REFERENCES public.workflows(id) ON DELETE CASCADE;


--
-- Name: slack_integration_audit_log slack_integration_audit_log_integration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.slack_integration_audit_log
    ADD CONSTRAINT slack_integration_audit_log_integration_id_fkey FOREIGN KEY (integration_id) REFERENCES public.slack_integrations(id) ON DELETE CASCADE;


--
-- Name: slack_integration_audit_log slack_integration_audit_log_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.slack_integration_audit_log
    ADD CONSTRAINT slack_integration_audit_log_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: slack_integrations slack_integrations_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.slack_integrations
    ADD CONSTRAINT slack_integrations_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: slack_integrations slack_integrations_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.slack_integrations
    ADD CONSTRAINT slack_integrations_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: tenant_quotas tenant_quotas_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_quotas
    ADD CONSTRAINT tenant_quotas_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.organizations(id);


--
-- Name: user_audit_settings user_audit_settings_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_audit_settings
    ADD CONSTRAINT user_audit_settings_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_capability_grants user_capability_grants_granted_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_capability_grants
    ADD CONSTRAINT user_capability_grants_granted_by_fkey FOREIGN KEY (granted_by) REFERENCES public.users(id);


--
-- Name: user_capability_grants user_capability_grants_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_capability_grants
    ADD CONSTRAINT user_capability_grants_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_module_pins user_module_pins_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_module_pins
    ADD CONSTRAINT user_module_pins_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: user_module_pins user_module_pins_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_module_pins
    ADD CONSTRAINT user_module_pins_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_sessions user_sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_sessions
    ADD CONSTRAINT user_sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: webhook_dlq webhook_dlq_replayed_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_dlq
    ADD CONSTRAINT webhook_dlq_replayed_by_fkey FOREIGN KEY (replayed_by) REFERENCES public.users(id);


--
-- Name: webhook_dlq webhook_dlq_trigger_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_dlq
    ADD CONSTRAINT webhook_dlq_trigger_id_fkey FOREIGN KEY (trigger_id) REFERENCES public.webhook_triggers(id) ON DELETE SET NULL;


--
-- Name: webhook_processed_events webhook_processed_events_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_processed_events
    ADD CONSTRAINT webhook_processed_events_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: webhook_request_log webhook_request_log_listener_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_request_log
    ADD CONSTRAINT webhook_request_log_listener_id_fkey FOREIGN KEY (trigger_id) REFERENCES public.webhook_triggers(id) ON DELETE CASCADE;


--
-- Name: webhook_request_log webhook_request_log_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_request_log
    ADD CONSTRAINT webhook_request_log_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: webhook_triggers webhook_triggers_module_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_triggers
    ADD CONSTRAINT webhook_triggers_module_id_fkey FOREIGN KEY (module_id) REFERENCES public.modules(id) ON DELETE SET NULL;


--
-- Name: webhook_triggers webhook_triggers_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_triggers
    ADD CONSTRAINT webhook_triggers_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: webhook_triggers webhook_triggers_signing_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_triggers
    ADD CONSTRAINT webhook_triggers_signing_key_id_fkey FOREIGN KEY (signing_key_id) REFERENCES public.encryption_keys(id);


--
-- Name: webhook_triggers webhook_triggers_workflow_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_triggers
    ADD CONSTRAINT webhook_triggers_workflow_id_fkey FOREIGN KEY (workflow_id) REFERENCES public.workflows(id) ON DELETE CASCADE;


--
-- Name: workflow_alerts workflow_alerts_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_alerts
    ADD CONSTRAINT workflow_alerts_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: workflow_approval_gates workflow_approval_gates_continuation_workflow_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_approval_gates
    ADD CONSTRAINT workflow_approval_gates_continuation_workflow_id_fkey FOREIGN KEY (continuation_workflow_id) REFERENCES public.workflows(id) ON DELETE SET NULL;


--
-- Name: workflow_approval_gates workflow_approval_gates_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_approval_gates
    ADD CONSTRAINT workflow_approval_gates_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: workflow_execution_logs workflow_execution_logs_execution_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_execution_logs
    ADD CONSTRAINT workflow_execution_logs_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES public.workflow_executions(id) ON DELETE CASCADE;


--
-- Name: workflow_executions workflow_executions_actor_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_executions
    ADD CONSTRAINT workflow_executions_actor_id_fkey FOREIGN KEY (actor_id) REFERENCES public.actors(id) ON DELETE RESTRICT;


--
-- Name: workflow_executions_archive workflow_executions_archive_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_executions_archive
    ADD CONSTRAINT workflow_executions_archive_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: workflow_executions_archive workflow_executions_archive_replayed_from_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_executions_archive
    ADD CONSTRAINT workflow_executions_archive_replayed_from_id_fkey FOREIGN KEY (replayed_from_id) REFERENCES public.workflow_executions(id) ON DELETE SET NULL;


--
-- Name: workflow_executions workflow_executions_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_executions
    ADD CONSTRAINT workflow_executions_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: workflow_executions workflow_executions_output_enc_key_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_executions
    ADD CONSTRAINT workflow_executions_output_enc_key_id_fkey FOREIGN KEY (output_enc_key_id) REFERENCES public.encryption_keys(id);


--
-- Name: workflow_executions workflow_executions_replayed_from_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_executions
    ADD CONSTRAINT workflow_executions_replayed_from_id_fkey FOREIGN KEY (replayed_from_id) REFERENCES public.workflow_executions(id);


--
-- Name: workflow_executions workflow_executions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_executions
    ADD CONSTRAINT workflow_executions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: workflow_executions workflow_executions_workflow_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_executions
    ADD CONSTRAINT workflow_executions_workflow_id_fkey FOREIGN KEY (workflow_id) REFERENCES public.workflows(id) ON DELETE CASCADE;


--
-- Name: workflow_executions workflow_executions_workflow_version_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_executions
    ADD CONSTRAINT workflow_executions_workflow_version_id_fkey FOREIGN KEY (workflow_version_id) REFERENCES public.workflow_versions(id);


--
-- Name: workflow_module_refs workflow_module_refs_workflow_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_module_refs
    ADD CONSTRAINT workflow_module_refs_workflow_id_fkey FOREIGN KEY (workflow_id) REFERENCES public.workflows(id) ON DELETE CASCADE;


--
-- Name: workflow_nodes workflow_nodes_module_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_nodes
    ADD CONSTRAINT workflow_nodes_module_id_fkey FOREIGN KEY (module_id) REFERENCES public.modules(id) ON DELETE SET NULL;


--
-- Name: workflow_nodes workflow_nodes_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_nodes
    ADD CONSTRAINT workflow_nodes_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: workflow_nodes workflow_nodes_workflow_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_nodes
    ADD CONSTRAINT workflow_nodes_workflow_id_fkey FOREIGN KEY (workflow_id) REFERENCES public.workflows(id) ON DELETE CASCADE;


--
-- Name: workflow_reuse_events workflow_reuse_events_workflow_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_reuse_events
    ADD CONSTRAINT workflow_reuse_events_workflow_id_fkey FOREIGN KEY (workflow_id) REFERENCES public.workflows(id) ON DELETE CASCADE;


--
-- Name: workflow_schedules workflow_schedules_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_schedules
    ADD CONSTRAINT workflow_schedules_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: workflow_schedules workflow_schedules_workflow_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_schedules
    ADD CONSTRAINT workflow_schedules_workflow_id_fkey FOREIGN KEY (workflow_id) REFERENCES public.workflows(id) ON DELETE CASCADE;


--
-- Name: workflow_sla_thresholds workflow_sla_thresholds_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_sla_thresholds
    ADD CONSTRAINT workflow_sla_thresholds_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: workflow_sla_thresholds workflow_sla_thresholds_workflow_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_sla_thresholds
    ADD CONSTRAINT workflow_sla_thresholds_workflow_id_fkey FOREIGN KEY (workflow_id) REFERENCES public.workflows(id) ON DELETE CASCADE;


--
-- Name: workflow_suspensions workflow_suspensions_continuation_workflow_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_suspensions
    ADD CONSTRAINT workflow_suspensions_continuation_workflow_id_fkey FOREIGN KEY (continuation_workflow_id) REFERENCES public.workflows(id) ON DELETE SET NULL;


--
-- Name: workflow_suspensions workflow_suspensions_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_suspensions
    ADD CONSTRAINT workflow_suspensions_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: workflow_suspensions workflow_suspensions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_suspensions
    ADD CONSTRAINT workflow_suspensions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: workflow_versions workflow_versions_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_versions
    ADD CONSTRAINT workflow_versions_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: workflow_versions workflow_versions_workflow_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflow_versions
    ADD CONSTRAINT workflow_versions_workflow_id_fkey FOREIGN KEY (workflow_id) REFERENCES public.workflows(id) ON DELETE CASCADE;


--
-- Name: workflows workflows_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflows
    ADD CONSTRAINT workflows_agent_id_fkey FOREIGN KEY (actor_id) REFERENCES public.actors(id) ON DELETE SET NULL;


--
-- Name: workflows workflows_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.workflows
    ADD CONSTRAINT workflows_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id);


--
-- Name: actors; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.actors ENABLE ROW LEVEL SECURITY;

--
-- Name: actors actors_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY actors_tenant_isolation ON public.actors USING (((NULLIF(current_setting('app.current_user_id'::text, true), ''::text) IS NULL) OR (user_id = (NULLIF(current_setting('app.current_user_id'::text, true), ''::text))::uuid) OR (org_id = ANY ((string_to_array(NULLIF(current_setting('app.current_org_ids'::text, true), ''::text), ','::text))::uuid[])))) WITH CHECK (((NULLIF(current_setting('app.current_org_id'::text, true), ''::text) IS NULL) OR (org_id IS NULL) OR (org_id = (NULLIF(current_setting('app.current_org_id'::text, true), ''::text))::uuid)));


--
-- Name: scratch_sessions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.scratch_sessions ENABLE ROW LEVEL SECURITY;

--
-- Name: scratch_sessions scratch_sessions_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY scratch_sessions_tenant_isolation ON public.scratch_sessions USING (((user_id = (NULLIF(current_setting('app.current_user_id'::text, true), ''::text))::uuid) OR (org_id = ANY ((string_to_array(NULLIF(current_setting('app.current_org_ids'::text, true), ''::text), ','::text))::uuid[])))) WITH CHECK (((NULLIF(current_setting('app.current_user_id'::text, true), ''::text) IS NULL) OR (user_id = (NULLIF(current_setting('app.current_user_id'::text, true), ''::text))::uuid)));


--
-- Name: secrets; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.secrets ENABLE ROW LEVEL SECURITY;

--
-- Name: secrets secrets_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY secrets_tenant_isolation ON public.secrets USING (((NULLIF(current_setting('app.current_user_id'::text, true), ''::text) IS NULL) OR (owner_user_id = (NULLIF(current_setting('app.current_user_id'::text, true), ''::text))::uuid) OR (created_by = (NULLIF(current_setting('app.current_user_id'::text, true), ''::text))::uuid) OR (org_id = ANY ((string_to_array(NULLIF(current_setting('app.current_org_ids'::text, true), ''::text), ','::text))::uuid[])))) WITH CHECK ((((NULLIF(current_setting('app.current_org_id'::text, true), ''::text) IS NULL) OR (org_id IS NULL) OR (org_id = (NULLIF(current_setting('app.current_org_id'::text, true), ''::text))::uuid)) AND ((org_id IS NOT NULL) OR (NULLIF(current_setting('app.current_user_id'::text, true), ''::text) IS NULL) OR (owner_user_id IS NULL) OR (owner_user_id = (NULLIF(current_setting('app.current_user_id'::text, true), ''::text))::uuid))));


--
-- Name: user_module_pins; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.user_module_pins ENABLE ROW LEVEL SECURITY;

--
-- Name: user_module_pins user_module_pins_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY user_module_pins_tenant_isolation ON public.user_module_pins USING (((user_id = (NULLIF(current_setting('app.current_user_id'::text, true), ''::text))::uuid) OR (org_id = ANY ((string_to_array(NULLIF(current_setting('app.current_org_ids'::text, true), ''::text), ','::text))::uuid[])))) WITH CHECK (((NULLIF(current_setting('app.current_user_id'::text, true), ''::text) IS NULL) OR (user_id = (NULLIF(current_setting('app.current_user_id'::text, true), ''::text))::uuid)));


--
-- Name: workflow_executions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.workflow_executions ENABLE ROW LEVEL SECURITY;

--
-- Name: workflow_executions workflow_executions_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY workflow_executions_tenant_isolation ON public.workflow_executions USING (((NULLIF(current_setting('app.current_user_id'::text, true), ''::text) IS NULL) OR (user_id = (NULLIF(current_setting('app.current_user_id'::text, true), ''::text))::uuid) OR (EXISTS ( SELECT 1
   FROM public.workflows w
  WHERE ((w.id = workflow_executions.workflow_id) AND (w.org_id = ANY ((string_to_array(NULLIF(current_setting('app.current_org_ids'::text, true), ''::text), ','::text))::uuid[]))))))) WITH CHECK (((NULLIF(current_setting('app.current_user_id'::text, true), ''::text) IS NULL) OR (user_id = (NULLIF(current_setting('app.current_user_id'::text, true), ''::text))::uuid)));


--
-- Name: workflows; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.workflows ENABLE ROW LEVEL SECURITY;

--
-- Name: workflows workflows_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY workflows_tenant_isolation ON public.workflows USING (((NULLIF(current_setting('app.current_user_id'::text, true), ''::text) IS NULL) OR (user_id = (NULLIF(current_setting('app.current_user_id'::text, true), ''::text))::uuid) OR (org_id = ANY ((string_to_array(NULLIF(current_setting('app.current_org_ids'::text, true), ''::text), ','::text))::uuid[])))) WITH CHECK (((NULLIF(current_setting('app.current_org_id'::text, true), ''::text) IS NULL) OR (org_id IS NULL) OR (org_id = (NULLIF(current_setting('app.current_org_id'::text, true), ''::text))::uuid)));


--
-- Name: log_schema_changes; Type: EVENT TRIGGER; Schema: -; Owner: -
--

CREATE EVENT TRIGGER log_schema_changes ON ddl_command_end
   EXECUTE FUNCTION public.audit_schema_change();


--
-- PostgreSQL database dump complete
--


