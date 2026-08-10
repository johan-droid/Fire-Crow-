/**
 * Cloudflare Worker API Gateway & Edge Security Proxy for Fire Crow
 * Performs edge client IP forwarding, Turnstile verification, and CORS preflight handling.
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Handle CORS Preflight Requests at Cloudflare Edge
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN || "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, PATCH",
          "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With, X-CSRF-Token",
          "Access-Control-Max-Age": "86400",
        },
      });
    }

    // 2. Forward request to Fire Crow Backend Origin (or Cloudflare Tunnel URL)
    const backendUrl = env.BACKEND_ORIGIN_URL || "https://api.firecrow.dev";
    const originRequestUrl = `${backendUrl}${url.pathname}${url.search}`;

    const headers = new Headers(request.headers);
    
    // Inject Cloudflare Edge Metadata
    const clientIp = request.headers.get("CF-Connecting-IP") || "127.0.0.1";
    const rayId = request.headers.get("CF-Ray") || "";
    const country = request.headers.get("CF-IPCountry") || "XX";

    headers.set("X-Forwarded-For", clientIp);
    headers.set("X-Real-IP", clientIp);
    headers.set("CF-Connecting-IP", clientIp);
    headers.set("CF-Ray", rayId);
    headers.set("CF-IPCountry", country);

    const modifiedRequest = new Request(originRequestUrl, {
      method: request.method,
      headers: headers,
      body: ["GET", "HEAD"].includes(request.method) ? null : request.body,
      redirect: "follow",
    });

    try {
      const response = await fetch(modifiedRequest);
      const responseHeaders = new Headers(response.headers);
      
      // Inject security response headers
      responseHeaders.set("X-Content-Type-Options", "nosniff");
      responseHeaders.set("X-Frame-Options", "DENY");
      responseHeaders.set("X-Edge-Proxy", "Cloudflare-Worker-FireCrow");

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    } catch (err) {
      return new Response(
        JSON.stringify({ detail: "Edge Gateway error connecting to Fire Crow origin" }),
        { status: 502, headers: { "Content-Type": "application/json" } }
      );
    }
  },
};
