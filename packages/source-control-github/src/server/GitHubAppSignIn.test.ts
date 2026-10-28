import * as NodeCrypto from "@effect/platform-node/NodeCrypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "@effect/vitest";
import * as Deferred from "effect/Deferred";
import * as Effect from "effect/Effect";
import * as Fiber from "effect/Fiber";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Redacted from "effect/Redacted";
import { HttpClient, HttpClientResponse } from "effect/http";
import { ChildProcessSpawner } from "effect/process";
import * as TestClock from "effect/testing/TestClock";

import { DEFAULT_SERVER_SETTINGS } from "@t3tools/contracts";
import * as SourceControlHost from "@t3tools/source-control-core/server/SourceControlHost";
import { readSourceControlHostSettings } from "@t3tools/source-control-core/shared/definition";
import { applyServerSettingsPatch } from "@t3tools/shared/serverSettings";
import * as TestSourceControlHost from "@t3tools/source-control-testing/TestSourceControlHost";

import * as GitHubClient from "../shared/definition.ts";
import * as GitHubAppSignIn from "./GitHubAppSignIn.ts";
import * as GitHubCredentials from "./GitHubCredentials.ts";
import * as GitHubRequestPolicy from "./GitHubRequestPolicy.ts";

type Reply = { readonly status?: number; readonly body: unknown };
type Handler = (path: string, form: URLSearchParams, authorization?: string) => Reply;

const HOUR = 3_600_000;

const session = (overrides: Record<string, unknown> = {}) =>
  JSON.stringify({
    account: "octocat",
    accessToken: "ghu_current",
    accessTokenExpiresAt: 8 * HOUR,
    refreshToken: "ghr_current",
    refreshTokenExpiresAt: 4_000 * HOUR,
    ...overrides,
  });

function harness(options: {
  readonly handle: Handler;
  readonly signIns?: Record<string, string>;
  readonly tokens?: Record<string, string>;
  /** Without one, the server has no `gh` login to fall back to. */
  readonly ghSignedIn?: boolean;
  /** Holds a request open until it completes, to interleave other work with it. */
  readonly gate?: (path: string) => Effect.Effect<void>;
}) {
  const requests: Array<{ readonly path: string; readonly form: URLSearchParams }> = [];
  const http = HttpClient.make((request) =>
    Effect.suspend(() => options.gate?.(new URL(request.url).pathname) ?? Effect.void).pipe(
      Effect.map(() => {
        const url = new URL(request.url);
        const form = new URLSearchParams(
          request.body._tag === "Uint8Array" ? new TextDecoder().decode(request.body.body) : "",
        );
        requests.push({ path: url.pathname, form });
        const reply = options.handle(url.pathname, form, request.headers["authorization"]);
        return HttpClientResponse.fromWeb(
          request,
          new Response(JSON.stringify(reply.body), {
            status: reply.status ?? 200,
            headers: { "content-type": "application/json" },
          }),
        );
      }),
    ),
  );
  const run: SourceControlHost.SourceControlHost["Service"]["process"]["run"] = () =>
    Effect.succeed({
      exitCode: ChildProcessSpawner.ExitCode(0),
      stdout: options.ghSignedIn === false ? "" : "gh-token\n",
      stderr: "",
      stdoutTruncated: false,
      stderrTruncated: false,
    });
  const layer = GitHubCredentials.layer.pipe(
    Layer.provideMerge(
      TestSourceControlHost.layer({
        settings: applyServerSettingsPatch(DEFAULT_SERVER_SETTINGS, {
          sourceControlHosts: {
            github: { signIns: options.signIns ?? {}, tokens: options.tokens ?? {} },
          },
        }),
        process: { run },
      }),
    ),
    Layer.provide(NodeCrypto.layer),
    Layer.provide(Layer.succeed(HttpClient.HttpClient, http)),
  );
  return { layer, requests };
}

const savedSignIns = Effect.gen(function* () {
  const host = yield* SourceControlHost.SourceControlHost;
  const settings = yield* host.settings.get;
  return readSourceControlHostSettings(GitHubClient.settings, settings.sourceControlHosts.github)
    .signIns;
});

const deviceCode = {
  device_code: "device-1",
  user_code: "ABCD-1234",
  verification_uri: "https://github.com/login/device",
  expires_in: 900,
  interval: 5,
};

describe("GitHubAppSignIn", () => {
  beforeEach(() => {
    for (const name of ["GH_TOKEN", "GITHUB_TOKEN"]) vi.stubEnv(name, "");
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it.effect("finishes a device-flow sign-in and serves its token before GH_TOKEN", () => {
    vi.stubEnv("GH_TOKEN", "from-env");
    const answers = [
      { error: "authorization_pending" },
      { error: "slow_down", interval: 10 },
      {
        access_token: "ghu_new",
        expires_in: 28_800,
        refresh_token: "ghr_new",
        refresh_token_expires_in: 15_897_600,
      },
    ];
    const { layer, requests } = harness({
      handle: (path) =>
        path === "/login/device/code"
          ? { body: deviceCode }
          : path === "/login/oauth/access_token"
            ? { body: answers.shift() }
            : { body: { login: "octocat" } },
    });
    return Effect.gen(function* () {
      const signIn = yield* GitHubAppSignIn.GitHubAppSignIn;
      const prompt = yield* signIn.start("github.com");
      expect(prompt).toEqual({
        userCode: "ABCD-1234",
        verificationUri: "https://github.com/login/device",
        expiresAt: 900_000,
      });
      const waiting = yield* Effect.forkChild(signIn.wait("github.com"));
      yield* TestClock.adjust("20 seconds");
      expect(yield* Fiber.join(waiting)).toEqual({ account: "octocat" });

      // `slow_down` stretches the interval: polls at 5s, 10s, then 20s.
      const polls = requests.filter((request) => request.path === "/login/oauth/access_token");
      expect(polls).toHaveLength(3);
      expect(polls[0]?.form.get("client_id")).toBe(GitHubAppSignIn.GITHUB_APP_CLIENT_ID);
      expect(polls[0]?.form.get("device_code")).toBe("device-1");

      const credential = yield* (yield* GitHubCredentials.GitHubCredentials).get("github.com");
      expect(credential.source).toBe("app");
      expect(Redacted.value(credential.token)).toBe("ghu_new");
      expect(JSON.parse((yield* savedSignIns)["github.com"] ?? "")).toEqual({
        account: "octocat",
        accessToken: "ghu_new",
        accessTokenExpiresAt: 20_000 + 28_800_000,
        refreshToken: "ghr_new",
        refreshTokenExpiresAt: 20_000 + 15_897_600_000,
      });
    }).pipe(Effect.provide(layer));
  });

  it.effect("reports a sign-in cancelled on GitHub and saves nothing", () => {
    const { layer } = harness({
      handle: (path) =>
        path === "/login/device/code" ? { body: deviceCode } : { body: { error: "access_denied" } },
    });
    return Effect.gen(function* () {
      const signIn = yield* GitHubAppSignIn.GitHubAppSignIn;
      yield* signIn.start("github.com");
      const waiting = yield* Effect.forkChild(Effect.flip(signIn.wait("github.com")));
      yield* TestClock.adjust("5 seconds");
      expect((yield* Fiber.join(waiting)).reason).toBe("denied");
      expect(yield* savedSignIns).toEqual({});
    }).pipe(Effect.provide(layer));
  });

  it.effect("expires a code nobody entered", () => {
    const { layer } = harness({
      handle: (path) =>
        path === "/login/device/code"
          ? { body: { ...deviceCode, expires_in: 12 } }
          : { body: { error: "authorization_pending" } },
    });
    return Effect.gen(function* () {
      const signIn = yield* GitHubAppSignIn.GitHubAppSignIn;
      yield* signIn.start("github.com");
      const waiting = yield* Effect.forkChild(Effect.flip(signIn.wait("github.com")));
      yield* TestClock.adjust("15 seconds");
      expect((yield* Fiber.join(waiting)).reason).toBe("expired");
    }).pipe(Effect.provide(layer));
  });

  it.effect("refuses hosts the app is not registered on", () => {
    const { layer, requests } = harness({ handle: () => ({ body: {} }) });
    return Effect.gen(function* () {
      const signIn = yield* GitHubAppSignIn.GitHubAppSignIn;
      expect((yield* Effect.flip(signIn.start("ghe.acme.test"))).reason).toBe("unsupported");
      expect((yield* Effect.flip(signIn.wait("github.com"))).reason).toBe("not-started");
      expect(requests).toEqual([]);
    }).pipe(Effect.provide(layer));
  });

  it.effect("refreshes an expiring token once for concurrent requests", () => {
    const { layer, requests } = harness({
      signIns: { "github.com": session({ accessTokenExpiresAt: 3 * 60_000 }) },
      handle: () => ({
        body: {
          access_token: "ghu_refreshed",
          expires_in: 28_800,
          refresh_token: "ghr_refreshed",
          refresh_token_expires_in: 15_897_600,
        },
      }),
    });
    return Effect.gen(function* () {
      const credentials = yield* GitHubCredentials.GitHubCredentials;
      const tokens = yield* Effect.all(
        [credentials.get("github.com"), credentials.get("github.com")],
        { concurrency: "unbounded" },
      );
      expect(tokens.map((credential) => Redacted.value(credential.token))).toEqual([
        "ghu_refreshed",
        "ghu_refreshed",
      ]);
      expect(requests).toHaveLength(1);
      expect(requests[0]?.form.get("grant_type")).toBe("refresh_token");
      expect(requests[0]?.form.get("refresh_token")).toBe("ghr_current");
      expect(JSON.parse((yield* savedSignIns)["github.com"] ?? "").account).toBe("octocat");
    }).pipe(Effect.provide(layer));
  });

  it.effect("refreshes a token GitHub refused before it expired", () => {
    const { layer, requests } = harness({
      signIns: { "github.com": session() },
      handle: () => ({ body: { access_token: "ghu_refreshed", expires_in: 28_800 } }),
    });
    return Effect.gen(function* () {
      const credentials = yield* GitHubCredentials.GitHubCredentials;
      expect(Redacted.value((yield* credentials.get("github.com")).token)).toBe("ghu_current");
      yield* credentials.invalidate("github.com", Redacted.make("ghu_current"));
      expect(Redacted.value((yield* credentials.get("github.com")).token)).toBe("ghu_refreshed");
      expect(requests).toHaveLength(1);
    }).pipe(Effect.provide(layer));
  });

  it.effect("signs out and falls back to gh when GitHub refuses the refresh token", () => {
    const { layer } = harness({
      signIns: { "github.com": session({ accessTokenExpiresAt: 0 }) },
      handle: () => ({ body: { error: "bad_refresh_token" } }),
    });
    return Effect.gen(function* () {
      const credentials = yield* GitHubCredentials.GitHubCredentials;
      const credential = yield* credentials.get("github.com");
      expect(credential.source).toBe("gh");
      expect(Redacted.value(credential.token)).toBe("gh-token");
      expect(yield* savedSignIns).toEqual({});
    }).pipe(Effect.provide(layer));
  });

  it.effect("keeps the session when GitHub cannot be reached to refresh it", () => {
    const { layer } = harness({
      signIns: { "github.com": session({ accessTokenExpiresAt: 0 }) },
      handle: () => ({ status: 502, body: {} }),
    });
    return Effect.gen(function* () {
      const credentials = yield* GitHubCredentials.GitHubCredentials;
      expect((yield* Effect.flip(credentials.get("github.com")))._tag).toBe(
        "GitHubAppSessionError",
      );
      expect(Object.keys(yield* savedSignIns)).toEqual(["github.com"]);
    }).pipe(Effect.provide(layer));
  });

  it.effect("lets a token saved in Settings win over the sign-in", () => {
    const { layer, requests } = harness({
      signIns: { "github.com": session() },
      tokens: { "github.com": "saved-pat" },
      handle: () => ({ body: {} }),
    });
    return Effect.gen(function* () {
      const credential = yield* (yield* GitHubCredentials.GitHubCredentials).get("github.com");
      expect(credential.source).toBe("settings");
      expect(Redacted.value(credential.token)).toBe("saved-pat");
      expect(
        Option.isNone(yield* (yield* GitHubAppSignIn.GitHubAppSignIn).token("ghe.acme.test")),
      ).toBe(true);
      expect(requests).toEqual([]);
    }).pipe(Effect.provide(layer));
  });

  const installedOn = (path: string): Reply =>
    path === "/user/installations"
      ? {
          body: {
            installations: [
              { id: 1, repository_selection: "all", account: { login: "pingdotgg" } },
              { id: 2, repository_selection: "selected", account: { login: "acme" } },
            ],
          },
        }
      : path === "/user/installations/2/repositories"
        ? { body: { repositories: [{ full_name: "acme/one" }] } }
        : { status: 404, body: {} };

  it.effect("keeps the app off repositories it is not installed on", () => {
    const { layer, requests } = harness({
      signIns: { "github.com": session() },
      handle: installedOn,
    });
    return Effect.gen(function* () {
      const credentials = yield* GitHubCredentials.GitHubCredentials;
      const sourceFor = (repository?: string) =>
        credentials
          .get("github.com", repository)
          .pipe(Effect.map((credential) => credential.source));
      expect(yield* sourceFor()).toBe("app");
      expect(yield* sourceFor("PingDotGG/t3code")).toBe("app");
      expect(yield* sourceFor("acme/one")).toBe("app");
      expect(yield* sourceFor("acme/two")).toBe("gh");
      expect(yield* sourceFor("someone/else")).toBe("gh");
      // One read of the installations serves every repository until it goes stale.
      expect(requests.filter((request) => request.path === "/user/installations")).toHaveLength(1);
    }).pipe(Effect.provide(layer));
  });

  it.effect("reports which repositories the app reaches", () => {
    const { layer } = harness({ signIns: { "github.com": session() }, handle: installedOn });
    return Effect.gen(function* () {
      const signIn = yield* GitHubAppSignIn.GitHubAppSignIn;
      expect(yield* signIn.access("github.com", "pingdotgg/anything")).toBe("covered");
      expect(yield* signIn.access("github.com", "acme/two")).toBe("not-covered");
      expect(yield* signIn.access("ghe.acme.test", "acme/one")).toBe("signed-out");
    }).pipe(Effect.provide(layer));
  });

  it.effect("uses the app anyway when the server has no other credential", () => {
    const { layer } = harness({
      signIns: { "github.com": session() },
      handle: installedOn,
      ghSignedIn: false,
    });
    return Effect.gen(function* () {
      const credential = yield* (yield* GitHubCredentials.GitHubCredentials).get(
        "github.com",
        "someone/public-repo",
      );
      expect(credential.source).toBe("app");
    }).pipe(Effect.provide(layer));
  });

  it.effect("stays on the app when GitHub cannot list the installations", () => {
    const { layer } = harness({
      signIns: { "github.com": session() },
      handle: () => ({ status: 502, body: {} }),
    });
    return Effect.gen(function* () {
      const credential = yield* (yield* GitHubCredentials.GitHubCredentials).get(
        "github.com",
        "acme/two",
      );
      expect(credential.source).toBe("app");
      expect(yield* (yield* GitHubAppSignIn.GitHubAppSignIn).access("github.com", "acme/two")).toBe(
        "covered",
      );
    }).pipe(Effect.provide(layer));
  });

  it.effect("keeps the app session when GitHub refuses a different credential", () => {
    const { layer, requests } = harness({
      signIns: { "github.com": session() },
      handle: () => ({ body: { access_token: "ghu_refreshed" } }),
    });
    return Effect.gen(function* () {
      const credentials = yield* GitHubCredentials.GitHubCredentials;
      yield* credentials.invalidate("github.com", Redacted.make("gh-token"));
      expect(Redacted.value((yield* credentials.get("github.com")).token)).toBe("ghu_current");
      expect(requests).toEqual([]);
    }).pipe(Effect.provide(layer));
  });

  it.effect("does not bring a session back that was signed out while it refreshed", () => {
    const released = Deferred.makeUnsafe<void>();
    const requested = Deferred.makeUnsafe<void>();
    const { layer } = harness({
      signIns: { "github.com": session({ accessTokenExpiresAt: 0 }) },
      gate: () =>
        Deferred.succeed(requested, undefined).pipe(Effect.andThen(Deferred.await(released))),
      handle: () => ({ body: { access_token: "ghu_refreshed", expires_in: 28_800 } }),
    });
    return Effect.gen(function* () {
      const credentials = yield* GitHubCredentials.GitHubCredentials;
      const settings = yield* TestSourceControlHost.TestSourceControlHostSettings;
      const refreshing = yield* Effect.forkChild(credentials.get("github.com"));
      yield* Deferred.await(requested);
      yield* settings.update({ sourceControlHosts: { github: { signIns: {} } } });
      yield* Deferred.succeed(released, undefined);
      expect((yield* Fiber.join(refreshing)).source).toBe("gh");
      expect(yield* savedSignIns).toEqual({});
    }).pipe(Effect.provide(layer));
  });

  it.effect("cancels a sign-in so approving the code afterwards saves nothing", () => {
    const { layer, requests } = harness({
      handle: (path) =>
        path === "/login/device/code"
          ? { body: deviceCode }
          : { body: { access_token: "ghu_new", expires_in: 28_800 } },
    });
    return Effect.gen(function* () {
      const signIn = yield* GitHubAppSignIn.GitHubAppSignIn;
      yield* signIn.start("github.com");
      const waiting = yield* Effect.forkChild(Effect.flip(signIn.wait("github.com")));
      yield* signIn.cancel("github.com");
      yield* TestClock.adjust("10 seconds");
      expect((yield* Fiber.join(waiting)).reason).toBe("cancelled");
      expect(requests.map((request) => request.path)).toEqual(["/login/device/code"]);
      expect(yield* savedSignIns).toEqual({});
    }).pipe(Effect.provide(layer));
  });

  it.effect("matches a repository named as a URL or with its host", () => {
    const { layer } = harness({ signIns: { "github.com": session() }, handle: installedOn });
    return Effect.gen(function* () {
      const signIn = yield* GitHubAppSignIn.GitHubAppSignIn;
      expect(yield* signIn.access("github.com", "https://github.com/acme/one.git")).toBe("covered");
      expect(yield* signIn.access("github.com", "github.com/Acme/One")).toBe("covered");
    }).pipe(Effect.provide(layer));
  });
});

describe("scopeMethodsToRepository", () => {
  it.effect("scopes a call to the repository it names or the checkout it runs in", () => {
    const scoped = GitHubRequestPolicy.scopeMethodsToRepository({
      read: (_input: { readonly repository: string }) => GitHubRequestPolicy.GitHubRepositoryScope,
      push: (_input: { readonly context: { readonly remoteUrl: string } }) =>
        GitHubRequestPolicy.GitHubRepositoryScope,
      viewer: (_input: { readonly host: string }) => GitHubRequestPolicy.GitHubRepositoryScope,
    });
    return Effect.gen(function* () {
      expect(yield* scoped.read({ repository: "acme/one" })).toBe("acme/one");
      expect(yield* scoped.push({ context: { remoteUrl: "git@github.com:acme/two.git" } })).toBe(
        "acme/two",
      );
      expect(yield* scoped.viewer({ host: "github.com" })).toBeNull();
    });
  });
});
