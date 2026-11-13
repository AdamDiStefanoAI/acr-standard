import test from 'node:test';
import assert from 'node:assert/strict';
import {
  assertRunnableDecision, ACRDecisionError, ACRDeniedError, ACREscalatedError,
} from '../dist/index.js';

test('allow returns the original response', () => {
  const response = { decision: 'allow', reason: 'Within approved limits' };
  assert.strictEqual(assertRunnableDecision(response), response);
});

test('modify preserves the original response and modified action', () => {
  const modifiedAction = { tool_name: 'refund', parameters: { amount: 25 } };
  const response = { decision: 'modify', modified_action: modifiedAction };
  assert.strictEqual(assertRunnableDecision(response), response);
  assert.strictEqual(response.modified_action, modifiedAction);
  assert.deepEqual(response.modified_action.parameters, { amount: 25 });
});

for (const [decision, ErrorClass] of [
  ['deny', ACRDeniedError], ['escalate', ACREscalatedError],
]) {
  test(`${decision} throws its decision error and retains the response`, () => {
    const response = {
      decision,
      reason: `${decision} by synthetic policy`,
      ...(decision === 'escalate' ? { approval_request_id: 'synthetic-approval-001' } : {}),
    };
    assert.throws(() => assertRunnableDecision(response), error => {
      assert.ok(error instanceof ErrorClass);
      assert.ok(error instanceof ACRDecisionError);
      assert.equal(error.name, ErrorClass.name);
      assert.equal(error.message, response.reason);
      assert.strictEqual(error.response, response);
      if (decision === 'escalate') {
        assert.equal(error.response.approval_request_id, 'synthetic-approval-001');
      }
      return true;
    });
  });

  for (const reason of [undefined, null]) {
    test(`${decision} uses fallback for ${String(reason)} reason`, () => {
      const response = { decision, reason };
      assert.throws(() => assertRunnableDecision(response), error => {
        assert.ok(error instanceof ErrorClass);
        assert.equal(error.name, ErrorClass.name);
        assert.equal(error.message, `ACR decision '${decision}' blocked execution`);
        assert.strictEqual(error.response, response);
        return true;
      });
    });
  }
}
