import { service } from 'knifecycle';
import { YError } from 'yerror';
import ms from 'ms';
import jwt from 'jsonwebtoken';
import type { Dependencies, Service, ServiceInitializer } from 'knifecycle';
import type { SignOptions, Algorithm } from 'jsonwebtoken';
import type { LogService, TimeService } from 'common-services';

export const DEFAULT_JWT_SECRET_ENV_NAME = 'JWT_SECRET';

export interface JWT_CONFIG<
  T extends string extends T
    ? never
    : string = typeof DEFAULT_JWT_SECRET_ENV_NAME,
> {
  secretEnvName?: T;
  duration: string;
  tolerance?: string;
  algorithms: Array<string>;
}

export type JWT_ENV<
  T extends string extends T
    ? never
    : string = typeof DEFAULT_JWT_SECRET_ENV_NAME,
> = Record<T, string>;

/**
@typedef JWTSignResult
*/
export type JWTSignResult = {
  token: string;
  issuedAt: number;
  expiresAt: number;
  validAt: number;
};

export interface JWTService<PAYLOAD extends Record<string, unknown>> {
  sign: (payload: PAYLOAD, algorithm?: string) => Promise<JWTSignResult>;
  verify: (token: string) => Promise<PAYLOAD>;
}

export type JWTServiceConfig<
  T extends string extends T
    ? never
    : string = typeof DEFAULT_JWT_SECRET_ENV_NAME,
> = {
  JWT_SECRET_ENV_NAME?: T;
  JWT: JWT_CONFIG<T>;
};

export type JWTServiceDependencies<
  T extends string extends T
    ? never
    : string = typeof DEFAULT_JWT_SECRET_ENV_NAME,
> = JWTServiceConfig<T> & {
  ENV?: JWT_ENV<T>;
  time?: TimeService;
  log?: LogService;
};

export interface JWTServiceInitializer<
  PAYLOAD extends Record<string, unknown>,
  T extends string extends T
    ? never
    : string = typeof DEFAULT_JWT_SECRET_ENV_NAME,
> {
  (dependencies: JWTServiceDependencies<T>): Promise<JWTService<PAYLOAD>>;
}

/* Architecture Note #1: JWT service

This JWT service is a simple wrapper around the `jsonwebtoken` NPM
 module. It adds a level of abstraction simply providing a way to
 sign and verify JSON Web Tokens in my apps.

It also cast errors with `YError` ones and adds a tolerance for
 expired tokens so that clock drifts between instances won't be
 a problem.

 It also uses `Knifecycle` for a drop in dependency injection
 support in projects using Knifecycle.

Finally, it deal with promises which are more convenient than the
 original API.
*/

export default service(
  initJWT as unknown as ServiceInitializer<Dependencies, Service>,
  'jwt',
  ['?JWT_SECRET_ENV_NAME', '?ENV', 'JWT', '?log', '?time'],
) as typeof initJWT;

/**
 * Instantiate the JWT service
 * @function
 * @param  {Object}     services
 * The services to inject
 * @param  {Function}   [services.JWT_SECRET_ENV_NAME]
 * The environment variable name in which to pick-up the
 *  JWT secret
 * @param  {Object}   [services.ENV]
 * An environment object
 * @param  {Function}   services.JWT
 * The JWT service configuration object
 * @param  {Function}   [services.log]
 * A logging function
 * @param  {Function}   [services.time]
 * A function returning the current timestamp
 * @return {Promise<JWTService>}
 * A promise of the jwt service
 * @example
 * import initJWTService from 'jwt-service';
 *
 * const jwt = await initJWTService({
 *   JWT: {
 *     secret: 'secret',
 *     duration: '2d',
 *     tolerance: '2h',
 *     algorithms: ['HS256'],
 *   },
 *   log: console.log.bind(console),
 *   time: Date.now.bind(Date),
 * });
 *
 * const token = await jwt.sign({ my: 'payload' });
 */
async function initJWT<
  PAYLOAD extends Record<string, unknown>,
  T extends string extends T
    ? never
    : string = typeof DEFAULT_JWT_SECRET_ENV_NAME,
>({
  JWT_SECRET_ENV_NAME,
  ENV,
  JWT,
  time = Date.now.bind(Date),
  log = noop,
}: JWTServiceDependencies<T>): Promise<JWTService<PAYLOAD>> {
  const JWT_DURATION = readMS(JWT.duration, 'E_BAD_JWT_DURATION');
  const JWT_TOLERANCE = readMS(JWT.tolerance, 'E_BAD_JWT_TOLERANCE', 0);
  const secretName =
    JWT_SECRET_ENV_NAME ||
    JWT.secretEnvName ||
    (DEFAULT_JWT_SECRET_ENV_NAME as T);
  const jwtSecret = ENV?.[secretName] as string;

  if (!jwtSecret) {
    throw new YError('E_NO_JWT_SECRET');
  }
  if (!(JWT.algorithms && JWT.algorithms.length)) {
    throw new YError('E_NO_JWT_ALGORITHMS');
  }

  /**
   * @typedef JWTService
   */
  const jwtService: JWTService<PAYLOAD> = {
    sign,
    verify,
  };

  /**
   * Sign the given payload
   * @memberof JWTService
   * @param  {Object}   payload      The payload to sign
   * @param  {String}   [algorithm]  The signing algorithm
   * @return {Promise<JWTSignResult>}
   * A promise to be resolved with the signed token.
   * @example
   * const token = await jwt.sign({ my: 'payload' });
   */
  async function sign(
    payload: PAYLOAD,
    algorithm: string = JWT.algorithms[0],
  ): Promise<JWTSignResult> {
    const issuedAt = time();
    const expiresAt = issuedAt + JWT_DURATION;
    const validAt = issuedAt;

    if (!JWT.algorithms.includes(algorithm)) {
      throw new YError('E_UNKNOWN_ALGORYTHM', algorithm, JWT.algorithms);
    }

    const token = await new Promise<string>((resolve, reject) => {
      jwt.sign(
        JSON.stringify({
          ...payload,
          iat: Math.floor(issuedAt / 1000),
          exp: Math.floor(expiresAt / 1000),
          nbf: Math.floor(validAt / 1000),
        }),
        jwtSecret,
        {
          algorithm,
        } as SignOptions,
        (err, token: string | undefined) => {
          if (err) {
            reject(YError.wrap(err as Error, 'E_JWT', payload));
            return;
          }
          resolve(token as string);
        },
      );
    });

    return {
      token,
      issuedAt,
      expiresAt,
      validAt,
    };
  }

  /**
   * Verify and decode the given token
   * @memberof JWTService
   * @param  {String}   [token]  The token to decode
   * @return {Promise<Object>}
   * A promise to be resolved with the token payload.
   * @example
   * const payload = await jwt.verify('my.jwt.token');
   */
  async function verify(token: string): Promise<PAYLOAD> {
    return new Promise((resolve, reject) => {
      jwt.verify(
        token,
        jwtSecret,
        {
          algorithms: JWT.algorithms as unknown as Algorithm[],
          clockTolerance: Math.floor(JWT_TOLERANCE / 1000),
          clockTimestamp: Math.floor(time() / 1000),
        },
        (err, decoded) => {
          if (err) {
            if ('TokenExpiredError' === err.name) {
              reject(YError.wrap(err, 'E_JWT_EXPIRED', token));
              return;
            }
            if ('JsonWebTokenError' === err.name) {
              reject(YError.wrap(err, 'E_JWT_MALFORMED', token));
              return;
            }
            reject(YError.wrap(err, 'E_JWT', token));
            return;
          }
          resolve(decoded as PAYLOAD);
        },
      );
    });
  }

  log('info', 'JWT service initialized!');

  return jwtService;
}

function noop(...args: unknown[]) {
  args;
}

function readMS(
  value: string | undefined,
  errorCode: string,
  defaultValue: number | undefined = undefined,
): number {
  const isRequired = 'undefined' === typeof defaultValue;
  const hasValue = 'undefined' !== typeof value;
  const finalValue = hasValue ? (value as string) : '' + defaultValue;

  if (isRequired && !hasValue) {
    throw new YError(errorCode, value);
  }

  try {
    const computedDuration = ms(finalValue);

    if ('undefined' === typeof computedDuration) {
      throw new YError(errorCode, value);
    }

    return computedDuration;
  } catch (err) {
    throw YError.wrap(err as Error, errorCode, finalValue);
  }
}
