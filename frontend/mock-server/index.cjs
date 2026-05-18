// Minimal mock GraphQL server for the Talos frontend (CommonJS version).
// The project uses "type": "module", so we provide a .cjs file that can be
// executed with `node mock-server/index.cjs` from the npm script.

const { ApolloServer } = require('@apollo/server');
const { startStandaloneServer } = require('@apollo/server/standalone');

const typeDefs = `
  type Query {
    me: User
    workflows: [Workflow!]!
  }
  type Mutation {
    dummy: String
    login(input: LoginInput!): AuthResponse!
    signup(input: SignupInput!): AuthResponse!
    refreshToken: AuthResponse!
    logout: Boolean!
  }
  type Subscription { executionUpdates(executionId: UUID!): ExecutionUpdate! }
  type User { id: ID! email: String! name: String }
  type Workflow { id: ID! name: String! }
  type ExecutionUpdate { executionId: ID! nodeId: ID! status: String! logMessage: String }
  type AuthResponse {
    accessToken: String!
    refreshToken: String!
    user: User!
  }
  input LoginInput { email: String! password: String! }
  input SignupInput { email: String! password: String! name: String }
  scalar UUID
`;

const resolvers = {
  Query: {
    me: () => ({ id: '1', name: 'Mock User' }),
    workflows: () => [{ id: 'w1', name: 'Demo workflow' }],
  },
  Mutation: {
    dummy: () => 'ok',
    login: (_, args) => {
      console.log('Mock login called with', args);
      const { email, password } = args.input;
      return {
        accessToken: 'mock-access-token',
        refreshToken: 'mock-refresh-token',
        user: { id: '1', email, name: 'Mock User' },
      };
    },
    signup: (_, args) => {
      console.log('Mock signup called with', args);
      const { email, name } = args.input;
      return {
        accessToken: 'mock-access-token',
        refreshToken: 'mock-refresh-token',
        user: { id: '1', email, name: name || 'Mock User' },
      };
    },
    refreshToken: () => ({
      accessToken: 'mock-access-token',
      refreshToken: 'mock-refresh-token',
      user: { id: '1', email: 'mock@example.com', name: 'Mock User' },
    }),
    logout: () => true,
  },
  Subscription: {
    executionUpdates: {
      subscribe: async function* () {
        // No real events – placeholder to satisfy client expectations.
      },
    },
  },
};

async function startServer() {
  const server = new ApolloServer({ typeDefs, resolvers });
  const { url } = await startStandaloneServer(server, {
    // Use a non‑conflicting port for the mock server.
    listen: { port: 4003 },
    // Enable CORS for Vite’s dev server (credentials mode).
    // Explicitly whitelist the dev origin so the Access-Control-Allow-Origin
    // header is not the wildcard '*'. This satisfies `credentials: 'include'.
    // Use `origin: true` so the server reflects the request's Origin header.
    // This avoids the wildcard '*' when credentials are included.
    cors: { origin: true, credentials: true },
  });
  console.log(`🚀 Mock GraphQL server ready at ${url}`);
}

startServer();
