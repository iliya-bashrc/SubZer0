import assert from 'node:assert/strict';
import test from 'node:test';
import worker from '../worker/index.mjs';

test('forwards requests to the static-assets binding without changing the response', async () => {
  const request = new Request('https://preview.example.test/snapshot/manifest.json?check=1');
  const expected = new Response('{"schema_version":1}', {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
  let forwardedRequest;
  const env = {
    ASSETS: {
      fetch: async (receivedRequest) => {
        forwardedRequest = receivedRequest;
        return expected;
      },
    },
  };

  const actual = await worker.fetch(request, env);

  assert.strictEqual(forwardedRequest, request);
  assert.strictEqual(actual, expected);
  assert.equal(await actual.text(), '{"schema_version":1}');
});

test('returns a generic server error when the static-assets binding is missing', async () => {
  const response = await worker.fetch(new Request('https://preview.example.test/'), {});

  assert.equal(response.status, 500);
  assert.equal(response.headers.get('content-type'), 'text/plain; charset=utf-8');
  assert.equal(await response.text(), 'Static asset service unavailable');
});
