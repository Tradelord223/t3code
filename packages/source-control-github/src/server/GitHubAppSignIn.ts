import {
  SourceControlProviderKind,
  SourceControlSignInError,
  type SourceControlSignInFailure,
  type SourceControlSignInPrompt,
  type SourceControlSignInResult,
} from "@t3tools/contracts";
import * as SourceControlHost from "@t3tools/source-control-core/server/SourceControlHost";
import { readSourceControlHostSettings } from "@t3tools/source-control-core/shared/definition";
import * as Cache from "effect/Cache";
import * as Clock from "effect/Clock";
import * as Context from "effect/Context";
import * as Deferred from "effect/Deferred";
import * as Exit from "effect/Exit";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Fiber from "effect/Fiber";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Ref from "effect/Ref";
import * as Schema from "effect/Schema";
import * as Semaphore from "effect/Semaphore";
import { HttpClient, HttpClientRequest, HttpClientResponse } from "effect/http";

import * as GitHubClient from "../shared/definition.ts";

/** The public client ID of the T3 Code for GitHub app; the device flow needs no secret. */
export const GITHUB_APP_CLIENT_ID = "Iv23liqyA11dE4B8Y7Jl";

const KIND = SourceControlProviderKind.make("github");
const REQUEST_TIMEOUT = Duration.seconds(15);
// Refresh ahead of expiry so a token never lapses between the check and a long request.
const REFRESH_MARGIN_MS = Duration.toMillis(Duration.minutes(5));

const GitHubAppSession = Schema.Struct({
  account: Schema.String,
  accessToken: Schema.String,
  /** Null when the app hands out tokens that do not expire. */
  accessTokenExpiresAt: Schema.NullOr(Schema.Number),
  refreshToken: Schema.NullOr(Schema.String),
  refreshTokenExpiresAt: Schema.NullOr(Schema.Number),
});
type GitHubAppSession = typeof GitHubAppSession.Type;

const GitHubAppSessionJson = Schema.fromJsonString(GitHubAppSession);
const decodeSession = Schema.decodeUnknownOption(GitHubAppSessionJson);
const encodeSession = Schema.encodeSync(GitHubAppSessionJson);

// GitHub answers both token grants with HTTP 200 and puts refusals in `error`.
const TokenResponse = Schema.Struct({
  access_token: Schema.optional(Schema.String),
  expires_in: Schema.optional(Schema.Number),
  refresh_token: Schema.optional(Schema.String),
  refresh_token_expires_in: Schema.optional(Schema.Number),
  interval: Schema.optional(Schema.Number),
  error: Schema.optional(Schema.String),
  error_description: Schema.optional(Schema.String),
});

const DeviceCodeResponse = Schema.Struct({
  device_code: Schema.optional(Schema.String),
  user_code: Schema.optional(Schema.String),
  verification_uri: Schema.optional(Schema.String),
  expires_in: Schema.optional(Schema.Number),
  interval: Schema.optional(Schema.Number),
  error: Schema.optional(Schema.String),
  error_description: Schema.optional(Schema.String),
});

const Viewer = Schema.Struct({ login: Schema.String });

const Installations = Schema.Struct({
  installations: Schema.Array(
    Schema.Struct({
      id: Schema.Number,
      repository_selection: Schema.String,
      account: Schema.NullOr(Schema.Struct({ login: Schema.String })),
    }),
  ),
});

const InstallationRepositories = Schema.Struct({
  repositories: Schema.Array(Schema.Struct({ full_name: Schema.String })),
});

// Installing the app on another account should show up soon after the user comes back.
const COVERAGE_TTL = Duration.minutes(2);
const MAX_REPOSITORY_PAGES = 10;

/** Where the signed-in app reaches: accounts that installed it for all repositories, or listed ones. */
interface AppCoverage {
  readonly accounts: ReadonlySet<string>;
  readonly repositories: ReadonlySet<string>;
}

/** Whether the app sign-in reaches a repository; `signed-out` when the server is not signed in. */
export type GitHubAppAccess = "covered" | "not-covered" | "signed-out";

export class GitHubAppSessionError extends Schema.TaggedError<GitHubAppSessionError>()(
  "GitHubAppSessionError",
  { host: Schema.String, cause: Schema.Defect() },
) {
  override get message(): string {
    return `Could not refresh the ${GitHubClient.APP_SIGN_IN.appName} sign-in for ${this.host}. Check the server's connection to GitHub, or sign in again in Settings → Source Control.`;
  }
}

export class GitHubAppSignIn extends Context.Service<
  GitHubAppSignIn,
  {
    /** The signed-in access token for `host`, refreshed when due; none when not signed in. */
    readonly token: (host: string) => Effect.Effect<Option.Option<string>, GitHubAppSessionError>;
    /** Refreshes on the next `token`, after GitHub refused the current one. */
    readonly invalidate: (host: string) => Effect.Effect<void>;
    /**
     * Whether an installation covers `owner/name`. A check that fails answers `covered`, so a
     * GitHub hiccup neither moves requests off the app nor nags the user.
     */
    readonly access: (host: string, repository: string) => Effect.Effect<GitHubAppAccess>;
    readonly start: (
      host: string,
    ) => Effect.Effect<SourceControlSignInPrompt, SourceControlSignInError>;
    readonly wait: (
      host: string,
    ) => Effect.Effect<SourceControlSignInResult, SourceControlSignInError>;
  }
>()("@t3tools/source-control-github/server/GitHubAppSignIn") {}

interface PendingSignIn {
  readonly deferred: Deferred.Deferred<SourceControlSignInResult, SourceControlSignInError>;
  readonly fiber: Fiber.Fiber<boolean>;
}

const signInError = (host: string, reason: SourceControlSignInFailure, detail: string) =>
  new SourceControlSignInError({ provider: KIND, host, reason, detail });

/** @public */
export const make = Effect.gen(function* () {
  const sourceControlHost = yield* SourceControlHost.SourceControlHost;
  const httpClient = yield* HttpClient.HttpClient;
  const scope = yield* Effect.scope;
  const refreshLock = yield* Semaphore.make(1);
  const refused = yield* Ref.make<ReadonlySet<string>>(new Set());
  const pending = yield* Ref.make<ReadonlyMap<string, PendingSignIn>>(new Map());

  const isAppHost = (host: string) =>
    GitHubClient.APP_SIGN_IN.hosts.includes(host.trim().toLowerCase());

  const readSignIns = sourceControlHost.settings.get.pipe(
    Effect.map(
      (settings) =>
        readSourceControlHostSettings(
          GitHubClient.settings,
          settings.sourceControlHosts[GitHubClient.definition.kind],
        ).signIns,
    ),
    Effect.orElseSucceed((): Readonly<Record<string, string>> => ({})),
  );

  const readSession = (host: string) =>
    readSignIns.pipe(Effect.map((signIns) => decodeSession(signIns[host] ?? "")));

  const writeSession = Effect.fn("GitHubAppSignIn.writeSession")(function* (
    host: string,
    session: GitHubAppSession | null,
  ) {
    const signIns = { ...(yield* readSignIns) };
    if (session === null) delete signIns[host];
    else signIns[host] = encodeSession(session);
    yield* sourceControlHost.settings.update({
      sourceControlHosts: { [GitHubClient.definition.kind]: { signIns } },
    });
  });

  const postForm = <S extends Schema.Top>(
    host: string,
    path: string,
    body: Record<string, string>,
    schema: S,
  ) =>
    httpClient
      .execute(
        HttpClientRequest.post(`https://${host}${path}`).pipe(
          HttpClientRequest.setHeaders({ accept: "application/json", "user-agent": "t3code" }),
          HttpClientRequest.bodyUrlParams(body),
        ),
      )
      .pipe(
        Effect.flatMap(HttpClientResponse.filterStatusOk),
        Effect.flatMap(HttpClientResponse.schemaBodyJson(schema)),
        Effect.timeout(REQUEST_TIMEOUT),
      );

  const getJson = <S extends Schema.Top>(host: string, token: string, path: string, schema: S) =>
    httpClient
      .execute(
        HttpClientRequest.get(`https://api.${host}/${path}`).pipe(
          HttpClientRequest.setHeaders({
            accept: "application/vnd.github+json",
            authorization: `Bearer ${token}`,
            "user-agent": "t3code",
            "x-github-api-version": "2022-11-28",
          }),
        ),
      )
      .pipe(
        Effect.flatMap(HttpClientResponse.filterStatusOk),
        Effect.flatMap(HttpClientResponse.schemaBodyJson(schema)),
        Effect.timeout(REQUEST_TIMEOUT),
      );

  const viewerLogin = (host: string, token: string) =>
    getJson(host, token, "user", Viewer).pipe(Effect.map((viewer) => viewer.login));

  const sessionFrom = (
    account: string,
    now: number,
    response: typeof TokenResponse.Type & { readonly access_token: string },
  ): GitHubAppSession => ({
    account,
    accessToken: response.access_token,
    accessTokenExpiresAt:
      response.expires_in === undefined ? null : now + response.expires_in * 1_000,
    refreshToken: response.refresh_token ?? null,
    refreshTokenExpiresAt:
      response.refresh_token_expires_in === undefined
        ? null
        : now + response.refresh_token_expires_in * 1_000,
  });

  const refresh = Effect.fn("GitHubAppSignIn.refresh")(function* (
    host: string,
    session: GitHubAppSession,
  ) {
    const now = yield* Clock.currentTimeMillis;
    if (
      session.refreshToken === null ||
      (session.refreshTokenExpiresAt !== null && session.refreshTokenExpiresAt <= now)
    ) {
      yield* writeSession(host, null).pipe(Effect.ignore);
      return Option.none<string>();
    }
    const response = yield* postForm(
      host,
      "/login/oauth/access_token",
      {
        client_id: GITHUB_APP_CLIENT_ID,
        grant_type: "refresh_token",
        refresh_token: session.refreshToken,
      },
      TokenResponse,
    ).pipe(Effect.mapError((cause) => new GitHubAppSessionError({ host, cause })));
    if (response.access_token === undefined) {
      // A refused refresh token is final: the user revoked the app or the session lapsed.
      yield* Effect.logWarning("GitHub refused the app sign-in refresh; signing out.", {
        host,
        error: response.error,
      });
      yield* writeSession(host, null).pipe(Effect.ignore);
      return Option.none<string>();
    }
    const next = sessionFrom(session.account, now, {
      ...response,
      access_token: response.access_token,
    });
    yield* writeSession(host, next).pipe(
      Effect.mapError((cause) => new GitHubAppSessionError({ host, cause })),
    );
    return Option.some(next.accessToken);
  });

  const isFresh = (session: GitHubAppSession, now: number) =>
    session.accessTokenExpiresAt === null || now < session.accessTokenExpiresAt - REFRESH_MARGIN_MS;

  const token: GitHubAppSignIn["Service"]["token"] = Effect.fn("GitHubAppSignIn.token")(
    function* (rawHost) {
      const host = rawHost.trim().toLowerCase();
      if (!isAppHost(host)) return Option.none();
      const session = yield* readSession(host);
      if (Option.isNone(session)) return Option.none();
      const now = yield* Clock.currentTimeMillis;
      if (
        isFresh(session.value, now) &&
        !(yield* Ref.get(refused)).has(session.value.accessToken)
      ) {
        return Option.some(session.value.accessToken);
      }
      return yield* refreshLock.withPermits(1)(
        Effect.gen(function* () {
          // Another request may have refreshed while this one queued.
          const current = yield* readSession(host);
          if (Option.isNone(current)) return Option.none<string>();
          const refusedTokens = yield* Ref.get(refused);
          if (
            isFresh(current.value, yield* Clock.currentTimeMillis) &&
            !refusedTokens.has(current.value.accessToken)
          ) {
            return Option.some(current.value.accessToken);
          }
          return yield* refresh(host, current.value);
        }),
      );
    },
  );

  const invalidate: GitHubAppSignIn["Service"]["invalidate"] = Effect.fn(
    "GitHubAppSignIn.invalidate",
  )(function* (rawHost) {
    const session = yield* readSession(rawHost.trim().toLowerCase());
    if (Option.isNone(session)) return;
    const refusedToken = session.value.accessToken;
    yield* Ref.update(refused, (current) => new Set([...current, refusedToken]));
  });

  const poll = Effect.fn("GitHubAppSignIn.poll")(function* (
    host: string,
    deviceCode: string,
    expiresAt: number,
    initialInterval: number,
  ) {
    let interval = initialInterval;
    while (true) {
      yield* Effect.sleep(Duration.seconds(interval));
      const now = yield* Clock.currentTimeMillis;
      if (now >= expiresAt) {
        return yield* signInError(host, "expired", "The sign-in code expired. Start again.");
      }
      const answer = yield* postForm(
        host,
        "/login/oauth/access_token",
        {
          client_id: GITHUB_APP_CLIENT_ID,
          device_code: deviceCode,
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        },
        TokenResponse,
      ).pipe(Effect.option);
      // A dropped poll is retried on the next tick; the code stays valid until it expires.
      if (Option.isNone(answer)) continue;
      const response = answer.value;
      if (response.access_token !== undefined) {
        const accessToken = response.access_token;
        const account = yield* viewerLogin(host, accessToken).pipe(
          Effect.mapError(
            (cause) =>
              new SourceControlSignInError({
                provider: KIND,
                host,
                reason: "failed",
                detail:
                  "GitHub accepted the sign-in but would not say which account it belongs to.",
                cause,
              }),
          ),
        );
        yield* writeSession(
          host,
          sessionFrom(account, yield* Clock.currentTimeMillis, {
            ...response,
            access_token: accessToken,
          }),
        ).pipe(
          Effect.mapError(
            (cause) =>
              new SourceControlSignInError({
                provider: KIND,
                host,
                reason: "failed",
                detail: "The server could not save the sign-in.",
                cause,
              }),
          ),
        );
        return { account } satisfies SourceControlSignInResult;
      }
      switch (response.error) {
        case "authorization_pending":
          continue;
        case "slow_down":
          interval = response.interval ?? interval + 5;
          continue;
        case "expired_token":
          return yield* signInError(host, "expired", "The sign-in code expired. Start again.");
        case "access_denied":
          return yield* signInError(host, "denied", "The sign-in was cancelled on GitHub.");
        default:
          return yield* signInError(
            host,
            "failed",
            response.error_description ??
              `GitHub refused the sign-in (${response.error ?? "no reason given"}).`,
          );
      }
    }
  });

  const start: GitHubAppSignIn["Service"]["start"] = Effect.fn("GitHubAppSignIn.start")(
    function* (rawHost) {
      const host = rawHost.trim().toLowerCase();
      if (!isAppHost(host)) {
        return yield* signInError(
          host,
          "unsupported",
          `${GitHubClient.APP_SIGN_IN.appName} only signs in to ${GitHubClient.APP_SIGN_IN.hosts.join(", ")}. Use a token or the GitHub CLI for ${host}.`,
        );
      }
      const code = yield* postForm(
        host,
        "/login/device/code",
        { client_id: GITHUB_APP_CLIENT_ID },
        DeviceCodeResponse,
      ).pipe(
        Effect.mapError(
          (cause) =>
            new SourceControlSignInError({
              provider: KIND,
              host,
              reason: "failed",
              detail: "The server could not reach GitHub to start the sign-in.",
              cause,
            }),
        ),
      );
      if (
        code.device_code === undefined ||
        code.user_code === undefined ||
        code.verification_uri === undefined ||
        code.expires_in === undefined
      ) {
        return yield* signInError(
          host,
          "failed",
          code.error_description ??
            `GitHub would not start the sign-in (${code.error ?? "no reason given"}).`,
        );
      }
      const expiresAt = (yield* Clock.currentTimeMillis) + code.expires_in * 1_000;
      const deferred = yield* Deferred.make<SourceControlSignInResult, SourceControlSignInError>();
      const fiber = yield* poll(host, code.device_code, expiresAt, code.interval ?? 5).pipe(
        Effect.tap(() => Ref.set(refused, new Set())),
        Effect.tap(() => Cache.invalidate(coverage, host)),
        Deferred.into(deferred),
        Effect.forkIn(scope),
      );
      const previous = yield* Ref.modify(pending, (current) => [
        current.get(host),
        new Map(current).set(host, { deferred, fiber }),
      ]);
      if (previous !== undefined) {
        yield* Deferred.fail(
          previous.deferred,
          signInError(host, "failed", "A newer sign-in replaced this one."),
        );
        yield* Fiber.interrupt(previous.fiber);
      }
      return {
        userCode: code.user_code,
        verificationUri: code.verification_uri,
        expiresAt,
      } satisfies SourceControlSignInPrompt;
    },
  );

  const wait: GitHubAppSignIn["Service"]["wait"] = Effect.fn("GitHubAppSignIn.wait")(
    function* (rawHost) {
      const host = rawHost.trim().toLowerCase();
      const current = (yield* Ref.get(pending)).get(host);
      if (current === undefined) {
        return yield* signInError(host, "not-started", "No sign-in is in progress. Start again.");
      }
      return yield* Deferred.await(current.deferred);
    },
  );

  const coverageOf = Effect.fn("GitHubAppSignIn.coverageOf")(function* (host: string) {
    const accessToken = yield* token(host);
    if (Option.isNone(accessToken)) return null;
    const { installations } = yield* getJson(
      host,
      accessToken.value,
      "user/installations?per_page=100",
      Installations,
    );
    const accounts = new Set<string>();
    const repositories = new Set<string>();
    for (const installation of installations) {
      const login = installation.account?.login.toLowerCase();
      if (login === undefined) continue;
      if (installation.repository_selection === "all") {
        accounts.add(login);
        continue;
      }
      for (let page = 1; page <= MAX_REPOSITORY_PAGES; page++) {
        const listed = yield* getJson(
          host,
          accessToken.value,
          `user/installations/${installation.id}/repositories?per_page=100&page=${page}`,
          InstallationRepositories,
        );
        for (const repository of listed.repositories) {
          repositories.add(repository.full_name.toLowerCase());
        }
        if (listed.repositories.length < 100) break;
      }
    }
    return { accounts, repositories } satisfies AppCoverage;
  });

  const coverage = yield* Cache.makeWith(coverageOf, {
    capacity: 8,
    timeToLive: (exit) => (Exit.isSuccess(exit) ? COVERAGE_TTL : Duration.zero),
  });

  const access: GitHubAppSignIn["Service"]["access"] = Effect.fn("GitHubAppSignIn.access")(
    function* (rawHost, rawRepository) {
      const host = rawHost.trim().toLowerCase();
      const repository = rawRepository.trim().toLowerCase();
      if (!isAppHost(host) || Option.isNone(yield* readSession(host))) return "signed-out";
      const known = yield* Cache.get(coverage, host).pipe(Effect.option);
      if (Option.isNone(known)) return "covered";
      if (known.value === null) return "signed-out";
      const owner = repository.split("/")[0] ?? "";
      return known.value.accounts.has(owner) || known.value.repositories.has(repository)
        ? "covered"
        : "not-covered";
    },
  );

  return GitHubAppSignIn.of({ token, invalidate, access, start, wait });
});

export const layer = Layer.effect(GitHubAppSignIn, make);
