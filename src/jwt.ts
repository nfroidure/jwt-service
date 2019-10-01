import { autoInject, service, name } from 'knifecycle';
import YError from 'yerror';
import ms from 'ms';
import jwt from 'jsonwebtoken';

const DEFAULT_ENV: JWT_ENV = {};

interface JWT_CONFIG {
  secret?: string;
  duration: string;
  tolerance?: string;
  algorithms: Array<string>;
}

interface JWT_ENV {
  JWT_SECRET?: string;
}

type Payload = {
  [key: string]: any;
};

/**
@typedef JWTSignResult
*/
type JWTSignResult = {
  token: string;
  issuedAt: number;
  expiresAt: number;
  validAt: number;
};

interface JWTService {
  sign: (payload: Payload, algorithm?: string) => Promise<JWTSignResult>;
  verify: (token: string) => Promise<Payload>;
}

interface JWTServiceDependencies {
  ENV?: JWT_ENV;
  JWT: JWT_CONFIG;
  time?: () => number;
  log?: (...args: Array<any>) => void;
}

interface JWTServiceInitializer {
  (dependencies: JWTServiceDependencies): Promise<JWTService>;
}

/* Architecture Note #1: JWT service

This JWT service is a simple wrapper around the `jsonwebtoken` NPM
 module. It add a level of abstraction simply providing a way to
 sign and verify JSON Web Tokens in my apps.

It also cast error to `YError` ones and adds a tolerance for expired
 tokens so that clock drifts between instances won't be a problem.
It also uses `Knifecycle` for a drop in dependency injection
 support in projetcs using Knifecycle.

Finally, it deal with promises which are more convenient than the
 original API.
*/
const wrappedInitializer: JWTServiceInitializer = name(
  'jwt',
  service(autoInject(initJWT)),
);

export default wrappedInitializer;

/**
 * Instantiate the JWT service
 * @name initJWTService
 * @function
 * @param  {Object}     services
 * The services to inject
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
async function initJWT({
  ENV = DEFAULT_ENV,
  JWT,
  time = Date.now.bind(Date),
  log = noop,
}: JWTServiceDependencies): Promise<JWTService> {
  const JWT_DURATION = readMS(JWT.duration, 'E_BAD_JWT_DURATION');
  const JWT_TOLERANCE = readMS(JWT.tolerance, 'E_BAD_JWT_TOLERANCE', 0);
  const jwtSecret = ENV.JWT_SECRET || JWT.secret;

  if (!jwtSecret) {
    throw new YError('E_NO_JWT_SECRET');
  }
  if (!(JWT.algorithms && JWT.algorithms.length)) {
    throw new YError('E_NO_JWT_ALGORITHMS');
  }

  /**
  @typedef JWTService
*/
  const jwtService: JWTService = {
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
    payload: object,
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
        },
        (err, token: string) => {
          if (err) {
            reject(YError.wrap(err, 'E_JWT', payload));
            return;
          }
          resolve(token);
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
  async function verify(token) {
    return new Promise((resolve, reject) => {
      jwt.verify(
        token,
        jwtSecret,
        {
          algorithms: JWT.algorithms,
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
          resolve(decoded);
        },
      );
    });
  }

  log('info', 'JWT service initialized!');

  return jwtService;
}

// eslint-disable-next-line
function noop(...args: any[]): any {}

function readMS(
  value: string,
  errorCode: string,
  defaultValue: number | undefined = undefined,
) {
  const isRequired = 'undefined' === typeof defaultValue;
  const hasValue = 'undefined' !== typeof value;
  const finalValue = hasValue ? value : '' + defaultValue;

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
    throw YError.wrap(err, errorCode, finalValue);
  }
}
