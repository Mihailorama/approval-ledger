# Approval Ledger

Hash-bound human approval and idempotent dispatch for automated actions.

Approval Ledger is deliberately channel-neutral. It does not know about social
networks, email providers, recipients or credentials. It stores an action's
canonical JSON digest, required gate results, the approval attached to that
exact digest and one durable dispatch result.

## Install

~~~bash
pip install approval-ledger
~~~

## Example

~~~python
from approval_ledger import SQLiteLedger

ledger = SQLiteLedger("ledger.sqlite3")
action = ledger.create_action(
    {"target": "draft", "body": "Human-approved message"},
    required_gates=("artifact-qa",),
)
ledger.record_gate(action.id, action.digest, "artifact-qa", passed=True)
ledger.approve(action.id, action.digest, approver="editor@example.test")

receipt = ledger.dispatch(
    action.id,
    lambda payload, key: "provider-delivery-id",
)
assert receipt.status == "completed"
~~~

## Safety model

- A changed payload has a different SHA-256 digest and needs a new approval.
- Required gates must pass before approval.
- A dispatch reservation is durable before the callback runs.
- A transport exception produces indeterminate state; the library does not
  retry and risk duplicate delivery.
- The package makes no claim of legal approval, content compliance or
  cryptographic signer identity.

Use a real authenticated audit identity and an application-specific transport
outside this package.

## Development

~~~bash
PYTHONPATH=src python -m unittest discover -s tests -v
uv build
~~~

## License

MIT. See [LICENSE](LICENSE).
