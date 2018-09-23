import initJWTService from './jwt';

describe('jwt service', () => {
  const log = jest.fn();
  const time = jest.fn();

  afterEach(() => {
    log.mockReset();
    time.mockReset();
  });

  test('should sign data', async () => {
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

  test('should verify data', async () => {
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
      expect(err.code).toEqual('E_JWT_EXPIRED');
      expect({
        logs: log.mock.calls,
        times: time.mock.calls,
      }).toMatchSnapshot();
    }
  });
});
