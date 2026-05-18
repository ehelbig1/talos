// Global test setup for Vitest
import '@testing-library/jest-dom';

import { setupServer } from 'msw/node';
import { handlers } from './src/mocks/handlers';

// Mock for fetch if needed globally
globalThis.fetch = globalThis.fetch || (vi.fn(() =>
  Promise.resolve({ json: async () => ({}), ok: true })
) as any);


export const server = setupServer(...handlers);

beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

