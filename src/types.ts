export interface IRTIService {
  callRTI(payload: RTIRequest, config:Config): Promise<RTIResponse>;
}

export interface IRTILogger {
  log(level: 'audit' | 'error' | 'info' | 'warn', message: string, action?: string): Promise<void>;
  error(message: string, action?: string): Promise<void>;
  info(message: string, action?: string): Promise<void>;
}

export enum Mode {
  MONITORING,
  BLOCKING,
}

export enum RTIParams {
  API_KEY = 'ApiKey',
  TAG_HASH = 'TagHash',
  EVENT_TYPE = 'EventType',
  CLIENT_IP = 'ClientIP',
  TRUSTED_IP_HEADER = 'trustedIPHeader',
  REQUEST_URL = 'RequestURL',
  RESOURCE_TYPE = 'ResourceType',
  METHOD = 'Method',
  HOST = 'Host',
  USER_AGENT = 'UserAgent',
  ACCEPT = 'Accept',
  ACCEPT_LANGUAGE = 'AcceptLanguage',
  ACCEPT_ENCODING = 'AcceptEncoding',
  ACCEPT_CHARSET = 'AcceptCharset',
  HEADER_NAMES = 'HeaderNames',
  CHEQ_COOKIE = 'CheqCookie',
  CHEQ_COOKIE_NAME = '_cheq_rti',
  REQUEST_TIME = 'RequestTime',
  X_FORWARDED_FOR = 'XForwardedFor',
  REFERER = 'Referer',
  ORIGIN = 'Origin',
  X_REQUESTED_WHIT = 'XRequestedWith',
  CONNECTION = 'Connection',
  PRAGMA = 'Pragma',
  CACHE_CONTROL = 'CacheControl',
  CONTENT_TYPE = 'ContentType',
  TRUE_CLIENT_IP = 'TrueClientIP',
  X_REAL_IP = 'XRealIP',
  REMOTE_ADDRESS = 'RemoteAddr',
  FORWARDED = 'Forwarded',
  JA3 = 'JA3',
  CHANNEL = 'Channel',
  MIDDLEWARE_VERSION = 'MiddlewareVersion',
}

export enum EventType {
  PAGE_LOAD = 'page_load',
  ADD_PAYMENT = 'add_payment',
  ADD_TO_CART = 'add_to_cart',
  ADD_TO_WISHLIST = 'add_to_wishlist',
  REGISTRATION = 'registration',
  PURCHASE = 'purchase',
  SEARCH = 'search',
  START_TRAIL = 'start_trail',
  SUBSCRIBE = 'subscribe',
  FORM_SUBMISSION = 'form_submission',
  CUSTOM = 'custom',
  TOKEN_VALIDATION = 'token_validation',
}

export enum Action {
  ALLOW,
  CHALLENGE,
  BLOCK,
  REDIRECT
}

export type HeadersMap = { [key: string]: string };

export type RTIRequest = {
  eventType: EventType;
  url: string;
  ip: string;
  method: string;
  headers: HeadersMap;
  ja3?: string;
  channel?: string;
  resourceType?: string;
};

export type RTIResponse = {
  version: number;
  isInvalid: boolean;
  threatTypeCode: number;
  requestId: string;
  setCookie: string;
};

export type Config = {
  mode: Mode;
  apiKey: string;
  tagHash: string;
  redirectLocation?: string;
  blockRedirectCodes: number[];
  challengeCodes?: number[];
  ignorePaths?: string[];
  routeToEventType?: { path: string; method: string; event_type: EventType }[];
  ipHeader?: string;
};
