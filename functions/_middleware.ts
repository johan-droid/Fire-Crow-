// Cloudflare Pages Edge Middleware for Request Logging & Header Injection
export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);

  console.log(`[Cloudflare Edge Log] ${request.method} ${url.pathname} from ${request.headers.get("CF-Connecting-IP") || "unknown"}`);

  const response = await context.next();
  return response;
}
