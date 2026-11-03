import { handle } from "@astrojs/cloudflare/handler";
import { AuditWorkflow } from "./lib/workflow/audit";

/**
 * One Worker serves the Astro site and the audit APIs. Astro handles the
 * request path; the named Workflow export is what the `AUDIT_WORKFLOW` binding
 * points at.
 */
export { AuditWorkflow };

export default {
  async fetch(request, env, ctx) {
    return await handle(request, env, ctx);
  },
} satisfies ExportedHandler<Env>;
