import { proxyControlRequest } from "../../../lib/control-api";

type Context = { params: Promise<{ path: string[] }> };

async function handle(request: Request, context: Context) {
  const { path } = await context.params;
  return proxyControlRequest(path.join("/"), request);
}

export const GET = handle;
export const POST = handle;
export const PUT = handle;
export const DELETE = handle;
