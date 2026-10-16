
export interface Env {
  DB: D1Database;
}

export default {
  async fetch(
    request: Request,
    env: Env
  ): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/api/health") {
      try {
        const result = await env.DB
          .prepare("SELECT 1 AS conectado")
          .first();

        return Response.json({
          status: "online",
          banco: result?.conectado === 1
            ? "conectado"
            : "erro"
        });
      } catch {
        return Response.json(
          {
            status: "erro",
            banco: "indisponivel"
          },
          { status: 500 }
        );
      }
    }

    return new Response("Not Found", {
      status: 404
    });
  }
};
