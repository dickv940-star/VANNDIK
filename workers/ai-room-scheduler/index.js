export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/health") {
      return Response.json({ ok: true, service: "vanndik-ai-room-scheduler", schedule: "*/5 * * * *" });
    }
    return new Response("Not found", { status: 404 });
  },
  async scheduled(controller, env, ctx) {
    const base = String(env.VANNDIK_CMS_URL || "").replace(/\/$/, "");
    const cronToken = env.AI_JOBS_CRON_TOKEN || env.VANNDIK_CRON_TOKEN;
    if (!base || !cronToken) {
      console.error("Scheduler configuration is incomplete.");
      return;
    }
    const headers = { authorization: "Bearer " + cronToken };
    // Idempotently create one daily target for each configured agent/admin.
    // The CMS uses a Jakarta-date key, so repeated five-minute cron ticks do not duplicate targets.
    const targetResponse = await fetch(base + "/api/cms/ai-room/daily-targets/process", {
      method: "POST",
      headers
    });
    const targetDetail = await targetResponse.text();
    if (!targetResponse.ok) {
      console.error("VANNDIK daily target generation failed:", targetResponse.status, targetDetail.slice(0, 1000));
    } else {
      console.log("VANNDIK daily targets:", targetDetail.slice(0, 1000));
    }

    const response = await fetch(base + "/api/cms/ai-room/jobs/process", {
      method: "POST",
      headers
    });
    const detail = await response.text();
    if (!response.ok) {
      console.error("VANNDIK queue processing failed:", response.status, detail.slice(0, 1000));
      return;
    }
    console.log("VANNDIK AI queue:", detail.slice(0, 1000));
  }
};
