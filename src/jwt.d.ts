interface JWT_CONFIG {
  secret?: string;
  duration: string;
  tolerance?: string;
  algorithms: Array<string>;
}
interface JWT_ENV {
  JWT_SECRET?: string;
}
declare type Payload = {
  [key: string]: any;
};
/**
@typedef JWTSignResult
*/
declare type JWTSignResult = {
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
declare const wrappedInitializer: JWTServiceInitializer;
export default wrappedInitializer;
