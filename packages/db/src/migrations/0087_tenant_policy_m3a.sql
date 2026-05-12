ALTER TABLE "cluster_tenant_policies" ADD COLUMN "git_credentials_secret_id" uuid;--> statement-breakpoint
ALTER TABLE "cluster_tenant_policies" ADD COLUMN "cilium_dns_allowlist" text[] DEFAULT ARRAY[]::text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "cluster_tenant_policies" ADD COLUMN "cilium_egress_cidrs" text[] DEFAULT ARRAY[]::text[] NOT NULL;--> statement-breakpoint
ALTER TABLE "cluster_tenant_policies" ADD CONSTRAINT "cluster_tenant_policies_git_credentials_secret_id_company_secrets_id_fk" FOREIGN KEY ("git_credentials_secret_id") REFERENCES "public"."company_secrets"("id") ON DELETE set null ON UPDATE no action;
