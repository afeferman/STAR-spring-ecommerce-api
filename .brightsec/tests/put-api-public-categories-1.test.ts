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

test('PUT /api/public/categories/1', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['bopla', 'csrf', 'excessive_data_exposure', 'sqli', 'xss'],
      attackParamLocations: [AttackParamLocation.BODY]
    })
    .threshold(Severity.CRITICAL)
    .timeout(timeout)
    .run({
      method: HttpMethod.PUT,
      url: `${baseUrl}/api/public/categories/1`,
      body: JSON.stringify({ name: 'Updated Electronics', description: 'Updated description' }),
      headers: { 'Content-Type': 'application/json' }
    });
});
