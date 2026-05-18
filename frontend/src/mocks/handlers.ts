import { http, HttpResponse } from "msw";

interface GraphQLBody {
  query: string;
  variables?: Record<string, unknown>;
  operationName?: string;
}

export const handlers = [
  // CSRF seed handler
  http.get("*/graphql", () => {
    return new HttpResponse(null, {
      status: 200,
      headers: {
        "Set-Cookie": "csrf_token=test-csrf-token; Path=/; SameSite=Lax",
      },
    });
  }),

  // Generic handler using operation inspection
  http.post("*/graphql", async ({ request }) => {
    const body = (await request.json()) as GraphQLBody;
    const { query, variables, operationName } = body;

    if (operationName === "GetWorkflows" || query.includes("GetWorkflows")) {
      return HttpResponse.json({
        data: {
          workflows: [
            { id: "1", name: "Test Workflow", description: "A test workflow" },
          ],
        },
      });
    }

    if (query.includes("nodeTemplates")) {
      return HttpResponse.json({
        data: {
          nodeTemplates: [
            {
              id: "template-1",
              name: "HTTP Request",
              category: "http",
              description: "Send an HTTP request",
              configSchema: JSON.stringify({
                type: "object",
                properties: {
                  url: { type: "string", default: "https://api.example.com" },
                  method: { type: "string", default: "GET" },
                },
              }),
              icon: "🌐",
              allowedHosts: ["api.example.com"],
            },
          ],
        },
      });
    }

    if (query.includes("myModules")) {
      return HttpResponse.json({
        data: {
          myModules: [
            {
              id: "module-1",
              name: "Existing Module",
              sizeBytes: 1024,
              contentHash: "abc",
              compiledAt: new Date().toISOString(),
              config: "{}",
              capabilityWorld: "http",
              capabilityDescription: "Full HTTP access",
              importedInterfaces: ["wasi:http/types"],
            },
          ],
        },
      });
    }

    if (query.includes("createModuleFromTemplate")) {
      return HttpResponse.json({
        data: {
          createModuleFromTemplate: {
            id: "new-module-id",
            name:
              (variables as { input?: { name?: string } })?.input?.name ||
              "New Module",
          },
        },
      });
    }

    if (query.includes("workflowExecutionHistory")) {
      return HttpResponse.json({
        data: {
          workflowExecutionHistory: [
            {
              id: "exec-1",
              status: "completed",
              startedAt: new Date(Date.now() - 5000).toISOString(),
              durationMs: 120,
              errorMessage: null,
              outputData: JSON.stringify({ result: "ok" }),
            },
            {
              id: "exec-2",
              status: "failed",
              startedAt: new Date(Date.now() - 60000).toISOString(),
              durationMs: 45,
              errorMessage: "Network timeout",
              outputData: null,
            },
          ],
        },
      });
    }

    if (query.includes("GetModuleExecutionHistory")) {
      return HttpResponse.json({
        data: {
          moduleExecutionHistory: [
            {
              id: "exec-1",
              status: "completed",
              durationMs: 150,
              startedAt: new Date().toISOString(),
              errorMessage: null,
              outputData: JSON.stringify({ success: true }),
            },
          ],
        },
      });
    }

    if (query.includes("GetModuleExecutionLogs")) {
      return HttpResponse.json({
        data: {
          moduleExecutionLogs: [
            {
              id: "log-1",
              level: "info",
              message: "Execution started",
              createdAt: new Date().toISOString(),
              metadata: null,
            },
            {
              id: "log-2",
              level: "info",
              message: "Processed item 1",
              createdAt: new Date().toISOString(),
              metadata: null,
            },
          ],
        },
      });
    }

    if (query.includes("GetWorkflowExecutionHistory")) {
      return HttpResponse.json({
        data: {
          workflowExecutionHistory: [
            {
              id: "wf-exec-1",
              status: "completed",
              startedAt: new Date().toISOString(),
              completedAt: new Date().toISOString(),
              durationMs: 450,
              errorMessage: null,
              outputData: JSON.stringify({ result: "ok" }),
            },
          ],
        },
      });
    }

    return HttpResponse.json({
      data: {},
    });
  }),
];
