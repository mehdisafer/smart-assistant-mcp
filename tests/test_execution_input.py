"""Durable input admission must remain replayable after the execution finishes."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from smart_assistant_mcp.common import RuntimeFault
from smart_assistant_mcp.store import StateStore, TERMINAL


class ExecutionInputTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "runtime.sqlite3"
        self.store = StateStore(self.path)

    def running_job(self, key="job"):
        job, created = self.store.submit("owner", key, {"argv": ["fixture"]}, 2)
        self.assertTrue(created)
        self.assertTrue(self.store.transition(job["id"], {"QUEUED"}, "RUNNING"))
        return job["id"]

    def input_rows(self, job_id):
        with self.store.connection() as connection:
            return [dict(row) for row in connection.execute(
                "SELECT * FROM inputs WHERE job_id=? ORDER BY sequence", (job_id,)
            )]

    def assert_fault(self, code, function, *args):
        with self.assertRaises(RuntimeFault) as caught:
            function(*args)
        self.assertEqual(caught.exception.code, code)

    def test_accepted_input_replays_after_every_terminal_state(self):
        for state in sorted(TERMINAL):
            with self.subTest(state=state):
                job_id = self.running_job(state)
                receipt = self.store.input(job_id, "owner", "answer\n", "input")
                self.assertEqual(len(self.store.claim_inputs(job_id)), 1)
                self.assertTrue(self.store.transition(job_id, {"RUNNING"}, state))
                before = self.input_rows(job_id)

                self.assertEqual(
                    self.store.input(job_id, "owner", "answer\n", "input"), receipt
                )
                self.assertEqual(self.input_rows(job_id), before)
                self.assertEqual(self.store.claim_inputs(job_id), [])
                self.assertEqual(self.store.get(job_id)["state"], state)

    def test_replay_survives_store_reopen(self):
        job_id = self.running_job()
        receipt = self.store.input(job_id, "owner", "answer\n", "input")
        self.store.claim_inputs(job_id)
        self.store.transition(job_id, {"RUNNING"}, "COMPLETED")

        reopened = StateStore(self.path)
        self.assertEqual(reopened.input(job_id, "owner", "answer\n", "input"), receipt)
        self.assertEqual(reopened.claim_inputs(job_id), [])

    def test_conflicting_terminal_replay_preserves_original_input(self):
        job_id = self.running_job()
        self.store.input(job_id, "owner", "original\n", "input")
        self.store.transition(job_id, {"RUNNING"}, "COMPLETED")
        before = self.input_rows(job_id)

        self.assert_fault("IDEMPOTENCY_CONFLICT", self.store.input,
                          job_id, "owner", "different\n", "input")
        self.assertEqual(self.input_rows(job_id), before)

    def test_terminal_execution_rejects_new_input(self):
        job_id = self.running_job()
        self.store.input(job_id, "owner", "original\n", "input")
        self.store.transition(job_id, {"RUNNING"}, "COMPLETED")
        before = self.input_rows(job_id)

        self.assert_fault("NOT_RUNNING", self.store.input,
                          job_id, "owner", "new\n", "new-key")
        self.assertEqual(self.input_rows(job_id), before)

    def test_other_owner_cannot_replay_an_accepted_input(self):
        job_id = self.running_job()
        self.store.input(job_id, "owner", "private\n", "input")
        before = self.input_rows(job_id)

        self.assert_fault("NOT_RUNNING", self.store.input,
                          job_id, "another-owner", "private\n", "input")
        self.assertEqual(self.input_rows(job_id), before)

    def test_missing_execution_does_not_admit_input(self):
        self.assert_fault("NOT_RUNNING", self.store.input,
                          "missing", "owner", "answer\n", "input")

    def test_full_queue_allows_replay_but_not_new_admission(self):
        job_id = self.running_job()
        receipt = self.store.input(job_id, "owner", "original\n", "input")
        for index in range(15):
            self.store.input(job_id, "owner", f"{index}\n", f"queued-{index}")
        before = self.input_rows(job_id)

        self.assertEqual(self.store.input(job_id, "owner", "original\n", "input"), receipt)
        self.assert_fault("INPUT_QUEUE_FULL", self.store.input,
                          job_id, "owner", "overflow\n", "overflow")
        self.assertEqual(self.input_rows(job_id), before)

    def test_running_replay_does_not_redeliver_claimed_input(self):
        job_id = self.running_job()
        receipt = self.store.input(job_id, "owner", "answer\n", "input")
        self.assertEqual(len(self.store.claim_inputs(job_id)), 1)

        self.assertEqual(self.store.input(job_id, "owner", "answer\n", "input"), receipt)
        self.assertEqual(self.store.claim_inputs(job_id), [])


if __name__ == "__main__":
    unittest.main()
