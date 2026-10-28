ALTER TABLE "alerts" ADD COLUMN "rule_id" varchar(100);--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "rule_name" varchar(255);--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "destination" varchar(255);--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "suggested_next_steps" text;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "related_log_ids" jsonb DEFAULT '[]'::jsonb;--> statement-breakpoint
ALTER TABLE "alerts" ADD COLUMN "dedup_key" varchar(255);--> statement-breakpoint
ALTER TABLE "logs" ADD COLUMN "source_port" integer;--> statement-breakpoint
ALTER TABLE "logs" ADD COLUMN "destination_port" integer;--> statement-breakpoint
ALTER TABLE "logs" ADD COLUMN "protocol" varchar(20);--> statement-breakpoint
ALTER TABLE "logs" ADD COLUMN "username" varchar(100);--> statement-breakpoint
ALTER TABLE "logs" ADD COLUMN "event_category" varchar(100);--> statement-breakpoint
CREATE INDEX "alerts_rule_id_idx" ON "alerts" USING btree ("rule_id");--> statement-breakpoint
CREATE INDEX "alerts_dedup_key_idx" ON "alerts" USING btree ("dedup_key");--> statement-breakpoint
CREATE INDEX "logs_source_type_idx" ON "logs" USING btree ("source_type");--> statement-breakpoint
CREATE INDEX "logs_username_idx" ON "logs" USING btree ("username");