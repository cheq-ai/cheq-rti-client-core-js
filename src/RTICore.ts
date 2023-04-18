import { Action, Config, EventType, HeadersMap, Mode, RTIParams, RTIRequest, RTIResponse } from './types';

export class RTICore {
  config: Config;
  constructor(config: Config) {
    this.config = config;
  }

  /**
   * Returns if the path should be ignored in {@link Mode.BLOCKING| Blocking Mode}
   * @param path
   */
  shouldIgnore(path: string): boolean {
    if (this.config.mode === Mode.BLOCKING && this.config.ignorePaths) {
      return this.config.ignorePaths.some(ignorePath => path.match(ignorePath));
    }
    return false;
  }

  /**
   * Returns event type for the given path and method, defaults to {@link EventType.PAGE_LOAD}
   * @param path
   * @param method
   */
  getEventType(path: string, method: string): EventType {
    if (this.config.routeToEventType) {
      const mapping = this.config.routeToEventType.find(
        mapping => path.match(mapping.path) && method.match(mapping.method),
      );
      if (mapping) {
        return mapping.event_type;
      }
    }
    return EventType.PAGE_LOAD;
  }

  /**
   * Returns the {@link Action} based on configuration and RTI response
   * @param rtiResponse
   */
  getAction(rtiResponse: RTIResponse): Action {
    if (this.config.mode === Mode.BLOCKING && rtiResponse.isInvalid) {
      if (this.config.blockRedirectCodes.includes(rtiResponse.threatTypeCode)) {
        return this.config.redirectLocation ? Action.REDIRECT : Action.BLOCK;
      } else if (this.config.challengeCodes && this.config.challengeCodes.includes(rtiResponse.threatTypeCode)) {
        return Action.CHALLENGE;
      }
    }
    return Action.ALLOW;
  }
}

/**
 * Returns the body for an RTI request
 * @param payload
 * @param config
 */
export function getBody(payload: RTIRequest, config: Config): { [key: string]: string | number | undefined } {
  const body: { [key: string]: string | number | undefined } = {};
  body[RTIParams.EVENT_TYPE] = payload.eventType;
  body[RTIParams.API_KEY] = config.apiKey;
  body[RTIParams.TAG_HASH] = config.tagHash;
  body[RTIParams.RESOURCE_TYPE] = payload.resourceType ?? 'text/html';
  body[RTIParams.CHEQ_COOKIE] = getCheqCookie(payload.headers.cookie);
  body[RTIParams.METHOD] = payload.method;
  body[RTIParams.CLIENT_IP] = config.trustedIPHeader
    ? getHeaderByName(payload.headers, config.trustedIPHeader, payload.ip)
    : payload.ip;
  body[RTIParams.REQUEST_URL] = payload.url;
  body[RTIParams.REQUEST_TIME] = new Date().getTime();
  body[RTIParams.HEADER_NAMES] = Object.keys(payload.headers).join(',');
  body[RTIParams.HOST] = getHeaderByName(payload.headers, 'x-cheq-rti-host', getHeaderByName(payload.headers, 'Host'));
  body[RTIParams.USER_AGENT] = getHeaderByName(payload.headers, 'User-Agent');
  body[RTIParams.X_FORWARDED_FOR] = getHeaderByName(payload.headers, 'X-Forwarded-For');
  body[RTIParams.REFERER] = getHeaderByName(payload.headers, 'Referer');
  body[RTIParams.ACCEPT] = getHeaderByName(payload.headers, 'Accept');
  body[RTIParams.ACCEPT_ENCODING] = getHeaderByName(payload.headers, 'Accept-Encoding');
  body[RTIParams.ACCEPT_LANGUAGE] = getHeaderByName(payload.headers, 'Accept-Language');
  body[RTIParams.ACCEPT_CHARSET] = getHeaderByName(payload.headers, 'Accept-Charset');
  body[RTIParams.ORIGIN] = getHeaderByName(payload.headers, 'Origin');
  body[RTIParams.X_REQUESTED_WITH] = getHeaderByName(payload.headers, 'X-Requested-With');
  body[RTIParams.CONNECTION] = getHeaderByName(payload.headers, 'Connection');
  body[RTIParams.PRAGMA] = getHeaderByName(payload.headers, 'Pragma');
  body[RTIParams.CACHE_CONTROL] = getHeaderByName(payload.headers, 'Cache-Control');
  body[RTIParams.CONTENT_TYPE] = getHeaderByName(payload.headers, 'Content-Type', '');
  body[RTIParams.TRUE_CLIENT_IP] = getHeaderByName(payload.headers, 'True-Client-IP');
  body[RTIParams.X_REAL_IP] = getHeaderByName(payload.headers, 'X-Real-IP');
  body[RTIParams.REMOTE_ADDRESS] = getHeaderByName(payload.headers, 'Remote-Addr');
  body[RTIParams.FORWARDED] = getHeaderByName(payload.headers, 'Forwarded');
  if (payload.ja3) {
    body[RTIParams.JA3] = payload.ja3;
  }
  if (payload.channel) {
    body[RTIParams.CHANNEL] = payload.channel;
  }
  return body;
}

/**
 * Returns CHEQ cookie value
 * @param cookie
 */
export function getCheqCookie(cookie: string) {
  return !cookie
    ? undefined
    : (
        cookie
          .split(';')
          .map(c => c.trim())
          .find(c => c.includes(RTIParams.CHEQ_COOKIE_NAME)) || ''
      ).substring(RTIParams.CHEQ_COOKIE_NAME.length + 1);
}

/**
 * Returns capitalized string and substrings
 * @param str
 * @param splitter
 */
export function capitalize(str = '', splitter = ' ') {
  return str
    .split(splitter)
    .map(s => `${s.charAt(0).toUpperCase()}${s.substring(1)}`)
    .join(splitter);
}

/**
 * Returns header ignoring case
 * @param headers
 * @param name
 * @param defaultValue
 */
export function getHeaderByName(headers: HeadersMap, name = '', defaultValue: string | number | undefined = undefined) {
  return headers[name.toLowerCase()] || headers[capitalize(name, '-')] || defaultValue;
}

/**
 * Validates configuration, returns list of errors found
 * @param config
 */
export function validateConfig(config: Config): string[] {
  const errors: string[] = [];
  if (config.blockRedirectCodes && config.challengeCodes) {
    const duplicates = config.blockRedirectCodes.filter(c => config.challengeCodes!.includes(c));
    if (duplicates.length > 0) {
      errors.push(
        `blockRedirectCodes and challengeCodes must be unique for each array, duplicates found: ${JSON.stringify(
          duplicates,
        )}`,
      );
    }
  }
  return errors;
}
