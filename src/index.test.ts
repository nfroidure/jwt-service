import { jest } from '@jest/globals';
import { YError } from 'yerror';
import initJWTService from './index.js';
import type { JWT_CONFIG } from './index.js';
import type { LogService, TimeService } from 'common-services';

describe('jwt service', () => {
  const log = jest.fn<LogService>();
  const time = jest.fn<TimeService>();

  afterEach(() => {
    log.mockReset();
    time.mockReset();
  });

  describe('initializer', () => {
    test('should fail without secret', async () => {
      try {
        await initJWTService({
          JWT: {
            duration: '2d',
            tolerance: '2h',
            algorithms: ['HS256'],
          },
          log,
          time,
        });
        throw new YError('E_UNEXPECTED_SUCCESS');
      } catch (err) {
        expect({
          errorCode: (err as YError).code,
          errorParams: (err as YError).params,
          logs: log.mock.calls,
          times: time.mock.calls,
        }).toMatchInlineSnapshot(`
          Object {
            "errorCode": "E_NO_JWT_SECRET",
            "errorParams": Array [],
            "logs": Array [],
            "times": Array [],
          }
        `);
      }
    });

    test('should fail without algorithms', async () => {
      try {
        await initJWTService({
          ENV: {
            JWT_SECRET: 'test',
          },
          JWT: {
            duration: '2d',
            tolerance: '2h',
            algorithms: [],
          },
          log,
          time,
        });
        throw new YError('E_UNEXPECTED_SUCCESS');
      } catch (err) {
        expect({
          errorCode: (err as YError).code,
          errorParams: (err as YError).params,
          logs: log.mock.calls,
          times: time.mock.calls,
        }).toMatchInlineSnapshot(`
          Object {
            "errorCode": "E_NO_JWT_ALGORITHMS",
            "errorParams": Array [],
            "logs": Array [],
            "times": Array [],
          }
        `);
      }
    });

    test('should fail without duration', async () => {
      try {
        await initJWTService({
          ENV: {
            JWT_SECRET: 'test',
          },
          JWT: {
            tolerance: '2h',
            algorithms: ['HS256'],
          } as JWT_CONFIG,
          log,
          time,
        });
        throw new YError('E_UNEXPECTED_SUCCESS');
      } catch (err) {
        expect({
          errorCode: (err as YError).code,
          errorParams: (err as YError).params,
          logs: log.mock.calls,
          times: time.mock.calls,
        }).toMatchInlineSnapshot(`
          Object {
            "errorCode": "E_BAD_JWT_DURATION",
            "errorParams": Array [],
            "logs": Array [],
            "times": Array [],
          }
        `);
      }
    });

    test('should fail with a bad tolerance', async () => {
      try {
        await initJWTService({
          ENV: {
            JWT_SECRET: 'test',
          },
          JWT: {
            duration: '2h',
            tolerance: '',
            algorithms: ['HS256'],
          },
          log,
          time,
        });
        throw new YError('E_UNEXPECTED_SUCCESS');
      } catch (err) {
        expect({
          errorCode: (err as YError).code,
          errorParams: (err as YError).params,
          logs: log.mock.calls,
          times: time.mock.calls,
        }).toMatchInlineSnapshot(`
          Object {
            "errorCode": "E_BAD_JWT_TOLERANCE",
            "errorParams": Array [
              "",
              "val is not a non-empty string or a valid number. val=\\"\\"",
            ],
            "logs": Array [],
            "times": Array [],
          }
        `);
      }
    });

    test('should fail with a uninterpreted duration', async () => {
      try {
        await initJWTService({
          ENV: {
            JWT_SECRET: 'test',
          },
          JWT: {
            duration: 'q',
            algorithms: ['HS256'],
          },
          log,
          time,
        });
        throw new YError('E_UNEXPECTED_SUCCESS');
      } catch (err) {
        expect({
          errorCode: (err as YError).code,
          errorParams: (err as YError).params,
          logs: log.mock.calls,
          times: time.mock.calls,
        }).toMatchInlineSnapshot(`
          Object {
            "errorCode": "E_BAD_JWT_DURATION",
            "errorParams": Array [
              "q",
            ],
            "logs": Array [],
            "times": Array [],
          }
        `);
      }
    });

    test('should fallback to default tolerance', async () => {
      await initJWTService({
        ENV: {
          JWT_SECRET: 'test',
        },
        JWT: {
          duration: '2h',
          algorithms: ['HS256'],
        },
        log,
        time,
      });
    });
  });

  describe('sign', () => {
    test('should work', async () => {
      time.mockReturnValueOnce(new Date('2014-01-26T00:00:00Z').getTime());

      const jwt = await initJWTService<{
        userId: number;
        organisationId: number;
      }>({
        ENV: {
          JWT_SECRET: 'secret',
        },
        JWT: {
          duration: '2d',
          tolerance: '2h',
          algorithms: ['HS256'],
        },
        log,
        time,
      });
      const token = await jwt.sign({
        userId: 2,
        organisationId: 3,
      });

      expect({
        token,
        logs: log.mock.calls,
        times: time.mock.calls,
      }).toMatchInlineSnapshot(`
        Object {
          "logs": Array [
            Array [
              "info",
              "JWT service initialized!",
            ],
          ],
          "times": Array [
            Array [],
          ],
          "token": Object {
            "expiresAt": 1390867200000,
            "issuedAt": 1390694400000,
            "token": "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOjIsIm9yZ2FuaXNhdGlvbklkIjozLCJpYXQiOjEzOTA2OTQ0MDAsImV4cCI6MTM5MDg2NzIwMCwibmJmIjoxMzkwNjk0NDAwfQ.DdWhIErffR-N-bTSsjr2tDOyinbMtYkL24IZxOVaB_0",
            "validAt": 1390694400000,
          },
        }
      `);
    });

    test('should work with an overriden config', async () => {
      time.mockReturnValueOnce(new Date('2014-01-26T00:00:00Z').getTime());

      const jwt = await initJWTService({
        JWT_SECRET_ENV_NAME: 'REFRESH_JWT_SECRET',
        ENV: {
          REFRESH_JWT_SECRET: 'secret',
        },
        JWT: {
          duration: '2d',
          tolerance: '2h',
          algorithms: ['HS256'],
        },
        log,
        time,
      });
      const token = await jwt.sign({
        userId: 2,
        organisationId: 3,
      });

      expect({
        token,
        logs: log.mock.calls,
        times: time.mock.calls,
      }).toMatchInlineSnapshot(`
        Object {
          "logs": Array [
            Array [
              "info",
              "JWT service initialized!",
            ],
          ],
          "times": Array [
            Array [],
          ],
          "token": Object {
            "expiresAt": 1390867200000,
            "issuedAt": 1390694400000,
            "token": "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOjIsIm9yZ2FuaXNhdGlvbklkIjozLCJpYXQiOjEzOTA2OTQ0MDAsImV4cCI6MTM5MDg2NzIwMCwibmJmIjoxMzkwNjk0NDAwfQ.DdWhIErffR-N-bTSsjr2tDOyinbMtYkL24IZxOVaB_0",
            "validAt": 1390694400000,
          },
        }
      `);
    });

    test('should fail with a bad algorithm', async () => {
      time.mockReturnValueOnce(new Date('2014-01-26T00:00:00Z').getTime());

      const jwt = await initJWTService({
        ENV: { SECRET_NAME: 'secret' },
        JWT: {
          secretEnvName: 'SECRET_NAME',
          duration: '2d',
          tolerance: '2h',
          algorithms: ['HS256'],
        },
        log,
        time,
      });

      try {
        await jwt.sign(
          {
            userId: 2,
            organisationId: 3,
          },
          'LOLALG',
        );
        throw new YError('E_UNEXPECTED_SUCCESS');
      } catch (err) {
        expect({
          errorCode: (err as YError).code,
          errorParams: (err as YError).params,
          logs: log.mock.calls,
          times: time.mock.calls,
        }).toMatchInlineSnapshot(`
          Object {
            "errorCode": "E_UNKNOWN_ALGORYTHM",
            "errorParams": Array [
              "LOLALG",
              Array [
                "HS256",
              ],
            ],
            "logs": Array [
              Array [
                "info",
                "JWT service initialized!",
              ],
            ],
            "times": Array [
              Array [],
            ],
          }
        `);
      }
    });
  });

  describe('verify', () => {
    test('should work', async () => {
      time.mockReturnValueOnce(new Date('2014-01-26T00:00:00Z').getTime());

      const jwt = await initJWTService({
        ENV: { SECRET_NAME: 'secret' },
        JWT: {
          secretEnvName: 'SECRET_NAME',
          duration: '2d',
          tolerance: '2h',
          algorithms: ['HS256'],
        },
        log,
        time,
      });
      const decoded = await jwt.verify(
        'eyJhbGciOiJIUzI1NiJ9.' +
          'eyJ1c2VySWQiOjIsIm9yZ2FuaXNhdGlvbklkIjozLCJpY' +
          'XQiOjEzOTA2OTQ0MDAsImV4cCI6MTM5MDg2NzIwMCwibmJmIjoxMzkwNjk0NDAwfQ.' +
          'DdWhIErffR-N-bTSsjr2tDOyinbMtYkL24IZxOVaB_0',
      );

      expect({
        decoded,
        logs: log.mock.calls,
        times: time.mock.calls,
      }).toMatchInlineSnapshot(`
        Object {
          "decoded": Object {
            "exp": 1390867200,
            "iat": 1390694400,
            "nbf": 1390694400,
            "organisationId": 3,
            "userId": 2,
          },
          "logs": Array [
            Array [
              "info",
              "JWT service initialized!",
            ],
          ],
          "times": Array [
            Array [],
          ],
        }
      `);
    });

    test('should fail after the validity duration', async () => {
      time.mockReturnValueOnce(new Date('2014-03-30T00:00:00Z').getTime());

      const jwt = await initJWTService({
        ENV: { SECRET_NAME: 'secret' },
        JWT: {
          secretEnvName: 'SECRET_NAME',
          duration: '2d',
          tolerance: '2h',
          algorithms: ['HS256'],
        },
        log,
        time,
      });

      try {
        await jwt.verify(
          'eyJhbGciOiJIUzI1NiJ9.' +
            'eyJ1c2VySWQiOjIsIm9yZ2FuaXNhdGlvbklkIjozLCJpY' +
            'XQiOjEzOTA2OTQ0MDAsImV4cCI6MTM5MDg2NzIwMCwibmJmIjoxMzkwNjk0NDAwfQ.' +
            'DdWhIErffR-N-bTSsjr2tDOyinbMtYkL24IZxOVaB_0',
        );
        throw new YError('E_UNEXPECTED_SUCCESS');
      } catch (err) {
        expect({
          errorCode: (err as YError).code,
          errorParams: (err as YError).params,
          logs: log.mock.calls,
          times: time.mock.calls,
        }).toMatchInlineSnapshot(`
          Object {
            "errorCode": "E_JWT_EXPIRED",
            "errorParams": Array [
              "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOjIsIm9yZ2FuaXNhdGlvbklkIjozLCJpYXQiOjEzOTA2OTQ0MDAsImV4cCI6MTM5MDg2NzIwMCwibmJmIjoxMzkwNjk0NDAwfQ.DdWhIErffR-N-bTSsjr2tDOyinbMtYkL24IZxOVaB_0",
              "jwt expired",
            ],
            "logs": Array [
              Array [
                "info",
                "JWT service initialized!",
              ],
            ],
            "times": Array [
              Array [],
            ],
          }
        `);
      }
    });

    test('should fail with a malformed token', async () => {
      time.mockReturnValueOnce(new Date('2014-03-30T00:00:00Z').getTime());

      const jwt = await initJWTService({
        ENV: { SECRET_NAME: 'secret' },
        JWT: {
          secretEnvName: 'SECRET_NAME',
          duration: '2d',
          tolerance: '2h',
          algorithms: ['HS256'],
        },
        log,
        time,
      });

      try {
        await jwt.verify('kikooolol');
        throw new YError('E_UNEXPECTED_SUCCESS');
      } catch (err) {
        expect({
          errorCode: (err as YError).code,
          errorParams: (err as YError).params,
          logs: log.mock.calls,
          times: time.mock.calls,
        }).toMatchInlineSnapshot(`
          Object {
            "errorCode": "E_JWT_MALFORMED",
            "errorParams": Array [
              "kikooolol",
              "jwt malformed",
            ],
            "logs": Array [
              Array [
                "info",
                "JWT service initialized!",
              ],
            ],
            "times": Array [
              Array [],
            ],
          }
        `);
      }
    });
  });
});
