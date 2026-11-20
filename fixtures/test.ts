import { test as base, expect, type APIRequestContext, type APIResponse, type Page } from '@playwright/test';

export const PASSWORD = 'Passw0rd!';

/** Seeded accounts, by the role they play in the tests. */
export const accounts = {
  admin: 'alice', // admin @ acme
  manager: 'bob', // manager @ acme
  member: 'carol', // member @ acme
  otherMember: 'dave', // member @ acme (owns the notes others try to reach)
  foreignAdmin: 'erin', // admin @ globex (other tenant)
  roleTarget: 'frank', // member @ acme, used for role-change tests
  lockoutTarget: 'lockme',
} as const;

export const userIds = { alice: 1, bob: 2, carol: 3, dave: 4, erin: 5, frank: 6, lockme: 7 } as const;

/** An API session for one user: sends cookies automatically and the CSRF header on writes. */
export class Session {
  constructor(
    readonly request: APIRequestContext,
    readonly csrfToken: string | undefined,
    readonly username: string | undefined,
  ) {}

  private headers(extra?: Record<string, string>) {
    return { ...(this.csrfToken ? { 'X-CSRF-Token': this.csrfToken } : {}), ...extra };
  }

  get(url: string): Promise<APIResponse> {
    return this.request.get(url);
  }
  post(url: string, data?: unknown, headers?: Record<string, string>): Promise<APIResponse> {
    return this.request.post(url, { data, headers: this.headers(headers) });
  }
  patch(url: string, data?: unknown, headers?: Record<string, string>): Promise<APIResponse> {
    return this.request.patch(url, { data, headers: this.headers(headers) });
  }
  delete(url: string, headers?: Record<string, string>): Promise<APIResponse> {
    return this.request.delete(url, { headers: this.headers(headers) });
  }

  /** Creates a note owned by this session's user and returns its id. */
  async createNote(fields: { title?: string; body?: string; private?: boolean } = {}): Promise<number> {
    const response = await this.post('/api/notes', { title: `Note ${Date.now()}`, ...fields });
    expect(response.status(), await response.text()).toBe(201);
    return (await response.json()).note.id;
  }
}

type Fixtures = {
  /** Logs in through the API and returns a session. Contexts are disposed after the test. */
  loginAs: (username: string) => Promise<Session>;
  /** A session with no cookies at all. */
  anonymous: Session;
  /** Logs a browser page in by calling the login API from the page's own context (shares cookies). */
  loginPage: (page: Page, username: string) => Promise<void>;
};

export const test = base.extend<Fixtures>({
  loginAs: async ({ playwright, baseURL }, use) => {
    const contexts: APIRequestContext[] = [];
    await use(async (username: string) => {
      const request = await playwright.request.newContext({ baseURL });
      contexts.push(request);
      const response = await request.post('/api/login', { data: { username, password: PASSWORD } });
      expect(response.status(), `login as ${username}`).toBe(200);
      const { csrfToken } = await response.json();
      return new Session(request, csrfToken, username);
    });
    await Promise.all(contexts.map((c) => c.dispose()));
  },

  anonymous: async ({ playwright, baseURL }, use) => {
    const request = await playwright.request.newContext({ baseURL });
    await use(new Session(request, undefined, undefined));
    await request.dispose();
  },

  loginPage: async ({}, use) => {
    await use(async (page: Page, username: string) => {
      const response = await page.request.post('/api/login', { data: { username, password: PASSWORD } });
      expect(response.status(), `login as ${username}`).toBe(200);
    });
  },
});

export { expect };
