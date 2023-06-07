declare module '@v57/noauth'

export function setServerSecret(secret: string): void;
export function getSecret(user: string): string;
export function auth(req: any, res: any, next: any): any;
export function tryAuth(req: any, res: any, next: any): void;
export function parseToken(token: string): string | undefined;
export function parseCachedToken(token: string): string | undefined;
export function cacheTokens(size: number): void;
