import initJWTService from './jwt';

describe('jwt service', () => {
  const log = jest.fn();
  const time = jest.fn();

  afterEach(() => {
    log.mockReset();
    time.mockReset();
  });

  describe('sign', () => {
    test('should work', async () => {
      time.mockReturnValueOnce(new Date('2014-01-26T00:00:00Z').getTime());

      const jwt = await initJWTService({
        JWT: {
          secret: 'secret',
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
      }).toMatchSnapshot();
    });

    test('should fail with a bad algorithm', async () => {
      time.mockReturnValueOnce(new Date('2014-01-26T00:00:00Z').getTime());

      const jwt = await initJWTService({
        JWT: {
          secret: 'secret',
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
        throw new Error('E_UNEXPECTED_SUCCESS');
      } catch (err) {
        expect({
          errorCode: err.code,
          errorParams: err.params,
          logs: log.mock.calls,
          times: time.mock.calls,
        }).toMatchSnapshot();
      }
    });
  });

  describe('verify', () => {
    test('should work', async () => {
      time.mockReturnValueOnce(new Date('2014-01-26T00:00:00Z').getTime());

      const jwt = await initJWTService({
        JWT: {
          secret: 'secret',
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
      }).toMatchSnapshot();
    });

    test('should fail after the validity duration', async () => {
      time.mockReturnValueOnce(new Date('2014-03-30T00:00:00Z').getTime());

      const jwt = await initJWTService({
        JWT: {
          secret: 'secret',
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
        throw new Error('E_UNEXPECTED_SUCCESS');
      } catch (err) {
        expect({
          errorCode: err.code,
          errorParams: err.params,
          logs: log.mock.calls,
          times: time.mock.calls,
        }).toMatchSnapshot();
      }
    });

    test('should fail with a malformed token', async () => {
      time.mockReturnValueOnce(new Date('2014-03-30T00:00:00Z').getTime());

      const jwt = await initJWTService({
        JWT: {
          secret: 'secret',
          duration: '2d',
          tolerance: '2h',
          algorithms: ['HS256'],
        },
        log,
        time,
      });

      try {
        await jwt.verify('kikooolol');
        throw new Error('E_UNEXPECTED_SUCCESS');
      } catch (err) {
        expect({
          errorCode: err.code,
          errorParams: err.params,
          logs: log.mock.calls,
          times: time.mock.calls,
        }).toMatchSnapshot();
      }
    });
  });
});
