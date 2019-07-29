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
interface JWTService {
  sign: (payload: Payload, algorithm?: string) => Promise<string>;
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
