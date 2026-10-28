CREATE TABLE "alerts" (
	"id" serial PRIMARY KEY NOT NULL,
	"severity" varchar(20) NOT NULL,
	"title" varchar(255) NOT NULL,
	"source" varchar(255) NOT NULL,
	"tactic" varchar(50) NOT NULL,
	"technique" varchar(50),
	"status" varchar(50) DEFAULT 'Open' NOT NULL,
	"detection_method" varchar(100) DEFAULT 'Rule-based' NOT NULL,
	"confidence" numeric(5, 2) DEFAULT '90.00' NOT NULL,
	"description" text,
	"evidence" jsonb DEFAULT '{}'::jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "cases" (
	"id" serial PRIMARY KEY NOT NULL,
	"case_number" varchar(50) NOT NULL,
	"alert_id" integer,
	"title" varchar(255) NOT NULL,
	"severity" varchar(20) DEFAULT 'High' NOT NULL,
	"status" varchar(50) DEFAULT 'Active' NOT NULL,
	"assigned_user_id" integer,
	"assigned_user_name" varchar(100) DEFAULT 'Avery Reed',
	"affected_asset" varchar(100) DEFAULT 'VPN Gateway' NOT NULL,
	"primary_entity" varchar(100) DEFAULT '185.220.101.45' NOT NULL,
	"mitre_technique" varchar(50) DEFAULT 'T1110' NOT NULL,
	"ai_confidence" numeric(5, 2) DEFAULT '94.80' NOT NULL,
	"summary" text,
	"timeline" jsonb DEFAULT '[]'::jsonb,
	"ai_explanation" text,
	"remediation_steps" jsonb DEFAULT '[]'::jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "cases_case_number_unique" UNIQUE("case_number")
);
--> statement-breakpoint
CREATE TABLE "logs" (
	"id" serial PRIMARY KEY NOT NULL,
	"timestamp" timestamp with time zone DEFAULT now() NOT NULL,
	"source_type" varchar(50) NOT NULL,
	"source_host" varchar(100),
	"source_ip" varchar(45),
	"destination_ip" varchar(45),
	"event_id" varchar(50),
	"log_level" varchar(20) DEFAULT 'INFO' NOT NULL,
	"raw_log" text NOT NULL,
	"parsed_fields" jsonb DEFAULT '{}'::jsonb,
	"is_threat" boolean DEFAULT false NOT NULL,
	"threat_reason" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "malware_samples" (
	"id" serial PRIMARY KEY NOT NULL,
	"filename" varchar(255) NOT NULL,
	"sha256" varchar(64) NOT NULL,
	"file_size" integer NOT NULL,
	"file_type" varchar(50) DEFAULT 'PE executable' NOT NULL,
	"verdict" varchar(50) DEFAULT 'Pending' NOT NULL,
	"confidence" numeric(5, 2) DEFAULT '0.00',
	"model_used" varchar(50) DEFAULT 'Static Analysis',
	"risk_score" numeric(3, 1) DEFAULT '0.0',
	"indicators" jsonb DEFAULT '[]'::jsonb,
	"pe_features" jsonb DEFAULT '{}'::jsonb,
	"status" varchar(50) DEFAULT 'Completed' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "network_flows" (
	"id" serial PRIMARY KEY NOT NULL,
	"source_host" varchar(100) NOT NULL,
	"source_ip" varchar(45) NOT NULL,
	"destination_host" varchar(100),
	"destination_ip" varchar(45) NOT NULL,
	"protocol" varchar(20) NOT NULL,
	"volume_bytes" bigint DEFAULT 0 NOT NULL,
	"volume_formatted" varchar(50) DEFAULT '0 KB' NOT NULL,
	"packet_count" integer DEFAULT 0,
	"risk" varchar(20) DEFAULT 'Low' NOT NULL,
	"anomaly_score" numeric(5, 2) DEFAULT '0.00',
	"is_anomaly" boolean DEFAULT false NOT NULL,
	"tags" jsonb DEFAULT '[]'::jsonb,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "reports" (
	"id" serial PRIMARY KEY NOT NULL,
	"report_code" varchar(50) NOT NULL,
	"title" varchar(255) NOT NULL,
	"incident_name" varchar(255) NOT NULL,
	"report_type" varchar(100) NOT NULL,
	"status" varchar(50) DEFAULT 'Draft' NOT NULL,
	"case_id" integer,
	"generated_by_id" integer,
	"content_json" jsonb DEFAULT '{}'::jsonb,
	"file_path" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "reports_report_code_unique" UNIQUE("report_code")
);
--> statement-breakpoint
CREATE TABLE "threat_intel_cache" (
	"id" serial PRIMARY KEY NOT NULL,
	"indicator" varchar(255) NOT NULL,
	"indicator_type" varchar(50) NOT NULL,
	"verdict" varchar(50) NOT NULL,
	"reputation_score" integer DEFAULT 0 NOT NULL,
	"detections_count" integer DEFAULT 0 NOT NULL,
	"total_engines" integer DEFAULT 0 NOT NULL,
	"confidence" varchar(20) DEFAULT 'High',
	"associated_context" jsonb DEFAULT '[]'::jsonb,
	"feed_verdicts" jsonb DEFAULT '[]'::jsonb,
	"first_seen" timestamp with time zone DEFAULT now(),
	"last_seen" timestamp with time zone DEFAULT now(),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "threat_intel_cache_indicator_unique" UNIQUE("indicator")
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" serial PRIMARY KEY NOT NULL,
	"email" varchar(255) NOT NULL,
	"password_hash" text NOT NULL,
	"full_name" varchar(100) NOT NULL,
	"role" varchar(50) DEFAULT 'Senior Analyst' NOT NULL,
	"initials" varchar(10) NOT NULL,
	"status" varchar(50) DEFAULT 'On shift' NOT NULL,
	"color" varchar(20) DEFAULT '#b7f960' NOT NULL,
	"active_cases_count" integer DEFAULT 0 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "users_email_unique" UNIQUE("email")
);
--> statement-breakpoint
ALTER TABLE "cases" ADD CONSTRAINT "cases_alert_id_alerts_id_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."alerts"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "cases" ADD CONSTRAINT "cases_assigned_user_id_users_id_fk" FOREIGN KEY ("assigned_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "reports" ADD CONSTRAINT "reports_case_id_cases_id_fk" FOREIGN KEY ("case_id") REFERENCES "public"."cases"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "reports" ADD CONSTRAINT "reports_generated_by_id_users_id_fk" FOREIGN KEY ("generated_by_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "alerts_severity_idx" ON "alerts" USING btree ("severity");--> statement-breakpoint
CREATE INDEX "alerts_status_idx" ON "alerts" USING btree ("status");--> statement-breakpoint
CREATE INDEX "alerts_created_at_idx" ON "alerts" USING btree ("created_at");--> statement-breakpoint
CREATE INDEX "cases_case_number_idx" ON "cases" USING btree ("case_number");--> statement-breakpoint
CREATE INDEX "cases_status_idx" ON "cases" USING btree ("status");--> statement-breakpoint
CREATE INDEX "logs_timestamp_idx" ON "logs" USING btree ("timestamp");--> statement-breakpoint
CREATE INDEX "logs_source_ip_idx" ON "logs" USING btree ("source_ip");--> statement-breakpoint
CREATE INDEX "logs_is_threat_idx" ON "logs" USING btree ("is_threat");--> statement-breakpoint
CREATE INDEX "malware_sha256_idx" ON "malware_samples" USING btree ("sha256");--> statement-breakpoint
CREATE INDEX "malware_status_idx" ON "malware_samples" USING btree ("status");--> statement-breakpoint
CREATE INDEX "network_source_ip_idx" ON "network_flows" USING btree ("source_ip");--> statement-breakpoint
CREATE INDEX "network_risk_idx" ON "network_flows" USING btree ("risk");--> statement-breakpoint
CREATE INDEX "reports_code_idx" ON "reports" USING btree ("report_code");--> statement-breakpoint
CREATE INDEX "reports_status_idx" ON "reports" USING btree ("status");--> statement-breakpoint
CREATE INDEX "threat_intel_indicator_idx" ON "threat_intel_cache" USING btree ("indicator");--> statement-breakpoint
CREATE INDEX "users_email_idx" ON "users" USING btree ("email");--> statement-breakpoint
CREATE INDEX "users_role_idx" ON "users" USING btree ("role");