declare module 'yerror' {
  interface YErrorRegistry {
    /** Thrown when the JWT duration is missing or invalid */
    E_BAD_JWT_DURATION: [] | [value?: string | number];

    /** Thrown when the JWT tolerance is invalid */
    E_BAD_JWT_TOLERANCE: [value: string | number];

    /** Thrown when the JWT secret environment variable is missing */
    E_NO_JWT_SECRET: [secretName: string];

    /** Thrown when no JWT algorithms are configured */
    E_NO_JWT_ALGORITHMS: [];

    /** Thrown when an unknown signing algorithm is requested */
    E_UNKNOWN_ALGORITHM: [algorithm: string, authorizedAlgorithms: string[]];

    /** Thrown when JSON Web Token operations fail */
    E_JWT: [payload: object] | [token: string];

    /** Thrown when the JWT token has expired */
    E_JWT_EXPIRED: [token: string];

    /** Thrown when the JWT token is malformed */
    E_JWT_MALFORMED: [token: string];
  }
}
