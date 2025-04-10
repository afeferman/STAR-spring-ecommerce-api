import { test, before, after } from 'node:test';
import { Severity, AttackParamLocation, HttpMethod } from '@sectester/scan';
import { SecRunner } from '@sectester/runner';

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

test('POST /api/public/categories', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'bopla', 'excessive_data_exposure', 'sqli', 'xss'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/public/categories`,
      body: JSON.stringify({ name: 'Electronics', description: 'Devices and gadgets' }),
      headers: { 'Content-Type': 'application/json' }
    });
});
