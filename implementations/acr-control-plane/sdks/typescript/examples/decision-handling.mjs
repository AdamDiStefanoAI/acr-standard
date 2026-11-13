import {
  assertRunnableDecision, ACRDeniedError, ACREscalatedError,
} from '../dist/index.js';

// Synthetic responses only. No HTTP, credentials, or real refunds.
const requestedAction = { tool_name: 'refund', parameters: { amount: 100 } };
const decisions = [
  { decision: 'allow' },
  { decision: 'modify', modified_action: { tool_name: 'refund', parameters: { amount: 25 } } },
  { decision: 'deny', reason: 'Refund forbidden by synthetic policy' },
  { decision: 'escalate', reason: 'Human approval required', approval_request_id: 'synthetic-approval-001' },
];

for (const response of decisions) {
  try {
    const runnable = assertRunnableDecision(response);
    // The helper does not apply modifications or execute a tool. The caller must
    // use the returned modified action, never silently reuse the original args.
    const action = runnable.decision === 'modify' ? runnable.modified_action : requestedAction;
    if (!action) throw new Error('Modified action missing; refusing execution');
    console.log(`${runnable.decision}: simulated ${action.tool_name} ${JSON.stringify(action.parameters)}`);
  } catch (error) {
    if (error instanceof ACRDeniedError) {
      console.log(`deny: no execution (${error.message})`);
    } else if (error instanceof ACREscalatedError) {
      console.log(`escalate: no execution; approval ${error.response.approval_request_id}`);
    } else {
      throw error;
    }
  }
}
