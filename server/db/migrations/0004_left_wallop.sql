CREATE TABLE "incident_explanations" (
	"id" serial PRIMARY KEY NOT NULL,
	"alert_id" integer NOT NULL,
	"provider" varchar(50) DEFAULT 'fallback' NOT NULL,
	"model" varchar(100),
	"status" varchar(30) DEFAULT 'pending' NOT NULL,
	"error_message" text,
	"evidence_snapshot_log_ids" jsonb DEFAULT '[]'::jsonb,
	"evidence_snapshot_alert_fields" jsonb DEFAULT '{}'::jsonb,
	"is_stale" boolean DEFAULT false NOT NULL,
	"executive_summary" text,
	"why_it_triggered" text,
	"evidence_narrative" text,
	"mitre_context" text,
	"potential_impact" text,
	"confidence_and_uncertainty" text,
	"investigation_steps" text,
	"containment_considerations" text,
	"missing_evidence" text,
	"generated_by_user_id" integer,
	"generated_by_user_name" varchar(100),
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "incident_explanations" ADD CONSTRAINT "incident_explanations_alert_id_alerts_id_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."alerts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_explanations" ADD CONSTRAINT "incident_explanations_generated_by_user_id_users_id_fk" FOREIGN KEY ("generated_by_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "explanations_alert_id_idx" ON "incident_explanations" USING btree ("alert_id");--> statement-breakpoint
CREATE INDEX "explanations_status_idx" ON "incident_explanations" USING btree ("status");--> statement-breakpoint
CREATE INDEX "explanations_created_at_idx" ON "incident_explanations" USING btree ("created_at");