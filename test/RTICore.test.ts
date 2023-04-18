import { getBody, RTICore, validateConfig } from '../src/RTICore';
import { Config, EventType, HeadersMap, Mode, RTIParams, RTIRequest } from '../src/types';

describe('validateConfig', () => {
  it('finds duplicate code errors', () => {
    const config: Config = {
      mode: Mode.BLOCKING,
      tagHash: 'foo',
      apiKey: 'bar',
      blockRedirectCodes: [1, 2],
      challengeCodes: [2],
    };
    const errors = validateConfig(config);
    expect(errors.length).toEqual(1);
    expect(errors[0]).toEqual(
      'blockRedirectCodes and challengeCodes must be unique for each array, duplicates found: [2]',
    );
  });

  it('validates minimum config', () => {
    const config: Config = {
      mode: Mode.MONITORING,
      tagHash: 'foo',
      apiKey: 'bar',
      blockRedirectCodes: [1, 2],
    };
    const errors = validateConfig(config);
    expect(errors.length).toEqual(0);
  });
});

describe('getBody', () => {
  it('gets host from x-cheq-rti-host header', () => {
    const body = getBody(getRequest({ 'x-cheq-rti-host': 'foo.com' }), getConfig());
    expect(body[RTIParams.HOST]).toEqual('foo.com');
  });

  it('falls back to host header', () => {
    const body = getBody(getRequest({ 'x-cheq-rti-host': '', host: 'foo.com' }), getConfig());
    expect(body[RTIParams.HOST]).toEqual('foo.com');
  });
});

describe('RTICore', () => {
  describe('shouldIgnore', () => {
    it('matches patterns', () => {
      const rtiCore = new RTICore(getConfig(['/images', '/api/test', '\\.css$', '\\.js$']));
      expect(rtiCore.shouldIgnore('/foo/bar.js')).toEqual(true);
      expect(rtiCore.shouldIgnore('/foo/1.css')).toEqual(true);
      expect(rtiCore.shouldIgnore('/images/test.png')).toEqual(true);
      expect(rtiCore.shouldIgnore('/api/test')).toEqual(true);
      expect(rtiCore.shouldIgnore('/api/css')).toEqual(false);
    });
  });
});

function getRequest(headers: HeadersMap): RTIRequest {
  return {
    headers,
    eventType: EventType.PAGE_LOAD,
    url: 'https://foo.com',
    method: 'GET',
    ip: '127.0.0.1',
  };
}

function getConfig(ignorePaths:string[] = []): Config {
  return {
    ignorePaths,
    mode: Mode.BLOCKING,
    tagHash: 'foo',
    apiKey: 'bar',
    blockRedirectCodes: [1, 2],
    challengeCodes: [2],
  };
}
