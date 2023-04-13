import { validateConfig } from '../src/RTICore';
import { Config, Mode } from '../src/types';

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
      blockRedirectCodes: [1, 2]
    };
    const errors = validateConfig(config);
    expect(errors.length).toEqual(0);
  });
});
