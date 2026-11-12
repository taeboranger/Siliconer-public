export const migrations = [{ version: 1, sql: `
CREATE TABLE organizations (id uuid PRIMARY KEY, name text NOT NULL);
CREATE TABLE users (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id),
 email text NOT NULL UNIQUE, password_hash text NOT NULL,
 role text NOT NULL CHECK(role IN ('admin','reviewer','developer','viewer')),
 created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(organization_id,id)
);
CREATE TABLE sessions (
 token_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 csrf_hash text NOT NULL, expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE integrations (
 id text PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id),
 kind text NOT NULL, name text NOT NULL, scope text NOT NULL,
 state text NOT NULL DEFAULT 'pending', last_success_at timestamptz, last_error text,
 updated_at timestamptz NOT NULL DEFAULT now(), UNIQUE(organization_id,id)
);
CREATE TABLE repositories (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id),
 integration_id text NOT NULL, full_name text NOT NULL, revision text NOT NULL,
 kind text NOT NULL, observed_at timestamptz NOT NULL,
 FOREIGN KEY(organization_id,integration_id) REFERENCES integrations(organization_id,id),
 UNIQUE(organization_id,integration_id,full_name), UNIQUE(organization_id,id)
);
CREATE TABLE applications (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id),
 integration_id text NOT NULL, external_uid text NOT NULL, name text NOT NULL,
 application_namespace text NOT NULL, project text NOT NULL,
 cluster_id text NOT NULL, namespace text NOT NULL, environment text NOT NULL DEFAULT 'prod',
 source_refs jsonb NOT NULL DEFAULT '[]', desired_images jsonb NOT NULL DEFAULT '[]',
 sync_state text NOT NULL DEFAULT 'Unknown', health_state text NOT NULL DEFAULT 'Unknown',
 render_state text NOT NULL DEFAULT 'unresolved', observed_at timestamptz NOT NULL,
 FOREIGN KEY(organization_id,integration_id) REFERENCES integrations(organization_id,id),
 UNIQUE(organization_id,integration_id,application_namespace,external_uid), UNIQUE(organization_id,id)
);
CREATE TABLE sboms (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id),
 repository text NOT NULL, commit_sha text NOT NULL, image text NOT NULL, digest text NOT NULL,
 workflow_run_id text NOT NULL, run_attempt integer NOT NULL, format text NOT NULL,
 content_hash text NOT NULL, raw_document jsonb NOT NULL, components jsonb NOT NULL,
 complete boolean NOT NULL, unsupported integer NOT NULL,
 provenance text NOT NULL CHECK(provenance IN ('verified','unverified')),
 collected_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(organization_id,digest,content_hash,provenance), UNIQUE(organization_id,id)
);
CREATE TABLE service_owners (
 organization_id uuid NOT NULL, user_id uuid NOT NULL, application_id uuid NOT NULL,
 FOREIGN KEY(organization_id,user_id) REFERENCES users(organization_id,id),
 FOREIGN KEY(organization_id,application_id) REFERENCES applications(organization_id,id),
 PRIMARY KEY(organization_id,user_id,application_id)
);
CREATE TABLE snapshots (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id),
 application_id uuid NOT NULL, cluster_id text NOT NULL, observed_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL, complete boolean NOT NULL, namespaces jsonb NOT NULL,
 containers jsonb NOT NULL, content_hash text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(organization_id,application_id) REFERENCES applications(organization_id,id),
 UNIQUE(organization_id,application_id,content_hash), UNIQUE(organization_id,id)
);
CREATE TABLE advisories (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id),
 canonical_id text NOT NULL, summary text NOT NULL, severity text NOT NULL,
 document jsonb NOT NULL, content_hash text NOT NULL, modified_at timestamptz NOT NULL,
 withdrawn boolean NOT NULL DEFAULT false, updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(organization_id,canonical_id), UNIQUE(organization_id,id)
);
CREATE TABLE advisory_revisions (
 id uuid PRIMARY KEY, advisory_id uuid NOT NULL REFERENCES advisories(id),
 content_hash text NOT NULL, document jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(advisory_id,content_hash)
);
CREATE TABLE advisory_aliases (
 organization_id uuid NOT NULL, alias text NOT NULL, advisory_id uuid NOT NULL,
 FOREIGN KEY(organization_id,advisory_id) REFERENCES advisories(organization_id,id),
 PRIMARY KEY(organization_id,alias)
);
CREATE TABLE findings (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id),
 advisory_id uuid NOT NULL, application_id uuid NOT NULL,
 status text NOT NULL CHECK(status IN ('affected','not_affected','under_investigation','fixed')),
 relevance text NOT NULL DEFAULT 'relevant', priority text NOT NULL DEFAULT 'medium',
 stale boolean NOT NULL DEFAULT false, summary text NOT NULL, evidence jsonb NOT NULL,
 fixed_versions jsonb NOT NULL DEFAULT '[]', input_hash text NOT NULL,
 expires_at timestamptz NOT NULL, assessed_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(organization_id,advisory_id) REFERENCES advisories(organization_id,id),
 FOREIGN KEY(organization_id,application_id) REFERENCES applications(organization_id,id),
 UNIQUE(organization_id,advisory_id,application_id), UNIQUE(organization_id,id)
);
CREATE TABLE assessments (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, finding_id uuid NOT NULL,
 status text NOT NULL, evidence jsonb NOT NULL, input_hash text NOT NULL, evaluator_version text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(organization_id,finding_id) REFERENCES findings(organization_id,id)
);
CREATE TABLE decisions (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, finding_id uuid NOT NULL,
 actor_id uuid NOT NULL, status text NOT NULL, rationale text NOT NULL,
 expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(organization_id,finding_id) REFERENCES findings(organization_id,id),
 FOREIGN KEY(organization_id,actor_id) REFERENCES users(organization_id,id)
);
CREATE TABLE tickets (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, finding_id uuid NOT NULL,
 status text NOT NULL DEFAULT 'open' CHECK(status IN ('open','in_progress','blocked','resolved')),
 assignee text NOT NULL DEFAULT '', notes text NOT NULL DEFAULT '', updated_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(organization_id,finding_id) REFERENCES findings(organization_id,id),
 UNIQUE(organization_id,finding_id)
);
CREATE TABLE jobs (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id),
 type text NOT NULL, payload jsonb NOT NULL, dedupe_key text NOT NULL,
 state text NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','running','succeeded','failed','blocked')),
 attempt integer NOT NULL DEFAULT 0, run_after timestamptz NOT NULL DEFAULT now(),
 lease_until timestamptz, lease_token uuid, error_code text,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX jobs_active_dedupe ON jobs(organization_id,dedupe_key) WHERE state IN ('queued','running');
CREATE INDEX jobs_claim ON jobs(state,run_after);
CREATE TABLE webhook_deliveries (
 integration_id text NOT NULL REFERENCES integrations(id), delivery_id text NOT NULL,
 received_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(integration_id,delivery_id)
);
CREATE TABLE reports (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, finding_id uuid NOT NULL,
 cache_key text NOT NULL, model text NOT NULL, body jsonb NOT NULL,
 expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(organization_id,finding_id) REFERENCES findings(organization_id,id),
 UNIQUE(organization_id,cache_key)
);
CREATE TABLE llm_budgets (
 organization_id uuid NOT NULL REFERENCES organizations(id), day date NOT NULL,
 reserved_usd numeric(14,8) NOT NULL DEFAULT 0, spent_usd numeric(14,8) NOT NULL DEFAULT 0,
 PRIMARY KEY(organization_id,day)
);
CREATE TABLE llm_usage (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id),
 job_id uuid, model text NOT NULL, state text NOT NULL, reserved_usd numeric(14,8) NOT NULL,
 actual_usd numeric(14,8), input_tokens integer, output_tokens integer, cached_tokens integer,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE audit_events (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id),
 actor text NOT NULL, action text NOT NULL, target text NOT NULL,
 details jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE notification_deliveries (
 organization_id uuid NOT NULL, event_hash text NOT NULL, sent_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,event_hash)
);
CREATE INDEX findings_current ON findings(organization_id,status,assessed_at);
CREATE INDEX sboms_digest ON sboms(organization_id,digest);
CREATE INDEX snapshots_current ON snapshots(organization_id,application_id,observed_at DESC);
` }, { version:2,sql:`ALTER TABLE reports ADD COLUMN context_evidence jsonb NOT NULL DEFAULT '[]';
ALTER TABLE reports ADD COLUMN finding_input_hash text NOT NULL DEFAULT '';` },{version:3,sql:`
CREATE TABLE investigations (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id), created_by uuid NOT NULL,
 title text NOT NULL, report_text text NOT NULL, reference_url text, scope jsonb NOT NULL,
 state text NOT NULL DEFAULT 'queued', stage text NOT NULL DEFAULT '요청 대기',
 plan jsonb, result jsonb, evidence jsonb NOT NULL DEFAULT '[]', error_code text,
 cache_key text NOT NULL, expires_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(organization_id,created_by) REFERENCES users(organization_id,id), UNIQUE(organization_id,id)
);
CREATE INDEX investigations_history ON investigations(organization_id,created_by,created_at DESC);
CREATE TABLE runtime_facts (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id), producer_id text NOT NULL,
 asset_id text NOT NULL, asset_kind text NOT NULL, display_name text NOT NULL, facts jsonb NOT NULL,
 observed_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, content_hash text NOT NULL,
 FOREIGN KEY(organization_id,producer_id) REFERENCES integrations(organization_id,id),
 UNIQUE(organization_id,producer_id,asset_id,content_hash)
);
` },{version:4,sql:`
ALTER TABLE tickets ALTER COLUMN finding_id DROP NOT NULL;
ALTER TABLE tickets ADD COLUMN source_key text;
ALTER TABLE tickets ADD COLUMN title text;
ALTER TABLE tickets ADD COLUMN target_id text;
ALTER TABLE tickets ADD COLUMN target_name text;
ALTER TABLE tickets ADD COLUMN assessment_status text;
ALTER TABLE tickets ADD COLUMN context jsonb NOT NULL DEFAULT '{}';
ALTER TABLE tickets ADD COLUMN assessment_hash text;
ALTER TABLE tickets ADD CONSTRAINT tickets_source CHECK (
 (finding_id IS NOT NULL AND source_key IS NULL) OR
 (finding_id IS NULL AND source_key IS NOT NULL AND target_id IS NOT NULL)
);
CREATE UNIQUE INDEX tickets_source_key ON tickets(organization_id,source_key) WHERE source_key IS NOT NULL;
ALTER TABLE tickets ADD CONSTRAINT tickets_org_id UNIQUE(organization_id,id);
CREATE TABLE investigation_tickets (
 organization_id uuid NOT NULL, investigation_id uuid NOT NULL, target_id text NOT NULL, ticket_id uuid NOT NULL,
 assessment jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(organization_id,investigation_id,target_id),
 FOREIGN KEY(organization_id,investigation_id) REFERENCES investigations(organization_id,id),
 FOREIGN KEY(organization_id,ticket_id) REFERENCES tickets(organization_id,id)
);
CREATE INDEX investigation_tickets_ticket ON investigation_tickets(organization_id,ticket_id);
` },{version:5,sql:`
ALTER TABLE llm_usage ADD COLUMN provider text NOT NULL DEFAULT 'openai';
CREATE TABLE llm_call_budgets (
 organization_id uuid NOT NULL REFERENCES organizations(id), day date NOT NULL, provider text NOT NULL,
 calls integer NOT NULL DEFAULT 0, PRIMARY KEY(organization_id,day,provider)
);
` },{version:6,sql:`
ALTER TABLE investigations ADD COLUMN started_at timestamptz;
ALTER TABLE investigations ADD COLUMN finished_at timestamptz;
ALTER TABLE investigations ADD COLUMN deleted_at timestamptz;
` },{version:7,sql:`
CREATE TABLE security_reports (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL REFERENCES organizations(id),
 created_by uuid NOT NULL, title text NOT NULL, body text NOT NULL, reference_url text,
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(organization_id,created_by) REFERENCES users(organization_id,id),
 UNIQUE(organization_id,id)
);
INSERT INTO security_reports(id,organization_id,created_by,title,body,reference_url,created_at)
 SELECT id,organization_id,created_by,title,report_text,reference_url,created_at FROM investigations;
ALTER TABLE investigations ADD COLUMN report_id uuid;
ALTER TABLE investigations ADD COLUMN analysis_settings jsonb NOT NULL DEFAULT '{}';
UPDATE investigations SET report_id=id;
ALTER TABLE investigations ADD CONSTRAINT investigations_report_fk
 FOREIGN KEY(organization_id,report_id) REFERENCES security_reports(organization_id,id);
CREATE INDEX security_reports_history ON security_reports(organization_id,created_at DESC,id);
ALTER TABLE llm_usage ADD COLUMN effort text NOT NULL DEFAULT 'low';
UPDATE investigations i SET analysis_settings=jsonb_build_object('model',prior.model,'effort',prior.effort)
 FROM (SELECT DISTINCT ON (j.payload->>'investigationId') j.payload->>'investigationId' AS investigation_id,u.model,u.effort
   FROM jobs j JOIN llm_usage u ON u.job_id=j.id AND u.organization_id=j.organization_id
   WHERE j.type='investigate' ORDER BY j.payload->>'investigationId',u.created_at ASC) prior
 WHERE i.id::text=prior.investigation_id;
ALTER TABLE jobs ADD COLUMN usage_context jsonb NOT NULL DEFAULT '{}';
CREATE TABLE model_accounts (
 organization_id uuid NOT NULL REFERENCES organizations(id),provider text NOT NULL,
 models jsonb NOT NULL DEFAULT '[]',limits jsonb NOT NULL DEFAULT '[]',
 observed_at timestamptz, error_code text, PRIMARY KEY(organization_id,provider)
);
CREATE TABLE investigation_details (
 id uuid PRIMARY KEY,organization_id uuid NOT NULL,investigation_id uuid NOT NULL,
 target_id text NOT NULL,model text NOT NULL,effort text NOT NULL,body jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(organization_id,investigation_id) REFERENCES investigations(organization_id,id),
 UNIQUE(organization_id,investigation_id,target_id,model,effort)
);
` },{version:8,sql:`
CREATE FUNCTION security_report_body_hash(report_body text) RETURNS bytea LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT sha256(convert_to(replace(replace(report_body,chr(13)||chr(10),chr(10)),chr(13),chr(10)),'UTF8'))
$$;
ALTER TABLE security_reports ADD COLUMN body_hash bytea GENERATED ALWAYS AS (security_report_body_hash(body)) STORED;
ALTER TABLE security_reports ADD COLUMN canonical_id uuid;
ALTER TABLE security_reports ADD CONSTRAINT security_reports_canonical_fk
 FOREIGN KEY(organization_id,canonical_id) REFERENCES security_reports(organization_id,id);
WITH ranked AS (
 SELECT id,first_value(id) OVER (PARTITION BY organization_id,body_hash,replace(replace(body,chr(13)||chr(10),chr(10)),chr(13),chr(10)) ORDER BY created_at,id) AS first_id
 FROM security_reports
)
UPDATE security_reports report SET canonical_id=ranked.first_id FROM ranked
 WHERE report.id=ranked.id AND ranked.id<>ranked.first_id;
UPDATE investigations i SET report_id=r.canonical_id FROM security_reports r
 WHERE i.organization_id=r.organization_id AND i.report_id=r.id AND r.canonical_id IS NOT NULL;
CREATE UNIQUE INDEX security_reports_unique_body ON security_reports(organization_id,body_hash) WHERE canonical_id IS NULL;
CREATE INDEX investigations_report_access ON investigations(organization_id,report_id,created_by);
` },{version:9,sql:`
ALTER TABLE users ADD COLUMN disabled_at timestamptz;
` },{version:10,sql:`
CREATE TABLE remediation_prs (
 organization_id uuid NOT NULL, ticket_id uuid NOT NULL REFERENCES tickets(id),
 repository text NOT NULL, number integer NOT NULL, title text NOT NULL, path text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(organization_id,ticket_id,repository,number)
);
` },{version:11,sql:`
CREATE TABLE image_runtime_versions (
 organization_id uuid NOT NULL, application_id uuid NOT NULL, digest text NOT NULL,
 container_name text NOT NULL, node_version text NOT NULL, brotli_version text NOT NULL,
 observed_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(organization_id,application_id) REFERENCES applications(organization_id,id),
 PRIMARY KEY(organization_id,application_id,digest,container_name)
);
` },{version:12,sql:`
CREATE TABLE llm_budget_settings (
 organization_id uuid PRIMARY KEY REFERENCES organizations(id),
 daily_calls integer NOT NULL CHECK(daily_calls BETWEEN 1 AND 1000),
 subscription_percent integer NOT NULL CHECK(subscription_percent BETWEEN 1 AND 100)
);
` },{version:13,sql:`
ALTER TABLE model_accounts ADD COLUMN account_email text;
ALTER TABLE model_accounts ADD COLUMN account_plan text;
CREATE TABLE codex_account_switches (
 id uuid PRIMARY KEY, organization_id uuid NOT NULL, requested_by uuid NOT NULL,
 state text NOT NULL CHECK(state IN ('queued','starting','waiting','completed','cancelled','failed')),
 user_code text, expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 error_code text,
 FOREIGN KEY(organization_id,requested_by) REFERENCES users(organization_id,id)
);
CREATE UNIQUE INDEX codex_one_account_switch ON codex_account_switches(organization_id) WHERE state IN ('queued','starting','waiting');
` }];
