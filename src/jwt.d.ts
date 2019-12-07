import { LogService, TimeService } from 'common-services';
export interface JWT_CONFIG {
  secret?: string;
  duration: string;
  tolerance?: string;
  algorithms: Array<string>;
}
export interface JWT_ENV {
  JWT_SECRET?: string;
}
export declare type Payload = {
  [key: string]: any;
};
/**
@typedef JWTSignResult
*/
export declare type JWTSignResult = {
  token: string;
  issuedAt: number;
  expiresAt: number;
  validAt: number;
};
export interface JWTService {
  sign: (payload: Payload, algorithm?: string) => Promise<JWTSignResult>;
  verify: (token: string) => Promise<Payload>;
}
export interface JWTServiceDependencies {
  ENV?: JWT_ENV;
  JWT: JWT_CONFIG;
  time?: TimeService;
  log?: LogService;
}
export interface JWTServiceInitializer {
  (dependencies: JWTServiceDependencies): Promise<JWTService>;
}
declare const wrappedInitializer: JWTServiceInitializer;
export default wrappedInitializer;
