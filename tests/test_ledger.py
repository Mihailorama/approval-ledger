import unittest

import approval_ledger


class ApprovalLedgerContractTest(unittest.TestCase):
    def test_canonical_digest_is_stable_across_mapping_order(self) -> None:
        first = approval_ledger.canonicalize({"body": "hello\r\nworld", "target": "draft"})
        second = approval_ledger.canonicalize({"target": "draft", "body": "hello\nworld"})

        self.assertEqual(first.digest, second.digest)
        self.assertEqual(first.payload, {"body": "hello\nworld", "target": "draft"})

    def test_dispatch_requires_exact_approval_and_is_idempotent(self) -> None:
        ledger = approval_ledger.SQLiteLedger(":memory:")
        action = ledger.create_action(
            {"target": "newsletter", "body": "Draft only"},
            required_gates=("artifact-qa",),
        )

        with self.assertRaises(approval_ledger.ApprovalError):
            ledger.approve(action.id, action.digest, approver="editor")

        ledger.record_gate(action.id, action.digest, "artifact-qa", passed=True)
        ledger.approve(action.id, action.digest, approver="editor")

        calls: list[str] = []

        def dispatch(payload: dict[str, object], idempotency_key: str) -> str:
            calls.append(idempotency_key)
            self.assertEqual(payload["body"], "Draft only")
            return "delivery-1"

        first = ledger.dispatch(action.id, dispatch)
        second = ledger.dispatch(action.id, dispatch)

        self.assertEqual(first.external_id, "delivery-1")
        self.assertEqual(second.external_id, "delivery-1")
        self.assertEqual(len(calls), 1)
