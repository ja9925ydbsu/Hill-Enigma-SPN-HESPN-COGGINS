#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path

from mds_rotor_core import (
    BASE_MDS, MDS_FAMILY, RotorSPN, SCHEDULES, derive_master_key,
    inverse_shift_rows, is_mds, minimal_schedule_period, rotate_matrix_k,
    self_check, shift_rows,
)
from mds_rotor_milp import solve_active_bound
from mds_rotor_trails import build_ddt, build_lat, sbox_statistics
from slide_reflection_audit import audit_all, compact_audit, slide_audit, reflection_audit


class CoreTests(unittest.TestCase):
    def test_rotation_order_four(self):
        self.assertEqual(rotate_matrix_k(BASE_MDS, 4), BASE_MDS)

    def test_all_orientations_mds(self):
        self.assertEqual(len(set(MDS_FAMILY)), 4)
        self.assertTrue(all(is_mds(matrix) for matrix in MDS_FAMILY))

    def test_shift_rows_inverse(self):
        state = list(range(16))
        self.assertEqual(inverse_shift_rows(shift_rows(state)), state)

    def test_cipher_roundtrip_all_schedules(self):
        key = derive_master_key("UNIT-TEST")
        plaintext = bytes(range(16))
        for name, schedule in SCHEDULES.items():
            with self.subTest(schedule=name):
                cipher = RotorSPN(key, schedule, rounds=8)
                self.assertEqual(cipher.decrypt_block(cipher.encrypt_block(plaintext)), plaintext)

    def test_self_check(self):
        result = self_check()
        self.assertEqual(result["branch_number_each_orientation"], 5)


class AnalysisTests(unittest.TestCase):
    def test_expected_milp_bounds(self):
        expected = {2: 5, 4: 25, 6: 30, 8: 50}
        for rounds, minimum in expected.items():
            with self.subTest(rounds=rounds):
                self.assertEqual(solve_active_bound(rounds).minimum_active_sboxes, minimum)

    def test_sbox_extrema(self):
        stats = sbox_statistics(build_ddt(), build_lat())
        self.assertEqual(stats["aes_sbox_max_ddt_count"], 4)
        self.assertEqual(stats["aes_sbox_max_abs_walsh"], 32)

    def test_schedule_periods(self):
        self.assertEqual(minimal_schedule_period(SCHEDULES["static"]), 1)
        self.assertEqual(minimal_schedule_period(SCHEDULES["rotor"]), 4)
        self.assertEqual(minimal_schedule_period(SCHEDULES["round_only"]), 4)
        self.assertEqual(minimal_schedule_period(SCHEDULES["position_only"]), 1)

    def test_no_exact_keyed_slide_repetition(self):
        key = derive_master_key("SLIDE-TEST")
        audit = slide_audit(key, SCHEDULES["rotor"], 16)
        self.assertEqual(audit["repeated_full_keyed_round_pairs"], [])


    def test_compact_audit_suppresses_long_lists(self):
        key = derive_master_key("COMPACT-AUDIT-TEST")
        detailed = audit_all(key, {"static": SCHEDULES["static"]}, 16)
        compact = compact_audit(detailed, example_limit=3)
        item = compact["variants"]["static"]
        self.assertEqual(item["slide"]["structural_repeat_pair_count"], 120)
        self.assertEqual(len(item["slide"]["structural_repeat_pair_examples"]), 3)
        self.assertNotIn("orientation_table", item["slide"])

    def test_reflection_audit_runs(self):
        key = derive_master_key("REFLECTION-TEST")
        audit = reflection_audit(key, SCHEDULES["rotor"], 16)
        self.assertFalse(audit["fixed_round_order_is_self_inverse"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
