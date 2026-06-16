import unittest
from monitor.diff import diff_analysis

class TestDiffAnalysis(unittest.TestCase):
    def test_diff_analysis_functionality(self):
        events_a = [
            {"type": "openat", "target": "/tmp/a", "pid": "1"},
            {"type": "connect", "target": "1.1.1.1", "pid": "1"},
        ]
        events_b = [
            {"type": "openat", "target": "/tmp/a", "pid": "2"},
            {"type": "connect", "target": "1.1.1.1", "pid": "2"},
            {"type": "connect", "target": "8.8.8.8", "pid": "2"},
            {"type": "write", "target": "/etc/shadow", "pid": "2"},
        ]

        result_a = {
            "parsed_data": {"events": events_a},
            "graph_data": {"stats": {"total_severity": 1.0}},
            "signature_matches": [{"name": "sig1"}]
        }
        result_b = {
            "parsed_data": {"events": events_b},
            "graph_data": {"stats": {"total_severity": 15.0}},
            "signature_matches": [{"name": "sig1"}, {"name": "sig2"}]
        }

        diff = diff_analysis(result_a, result_b)

        # Check syscall counts
        self.assertIn("write", diff["syscall_diff"]["added"])

        # Check network diff
        self.assertEqual(diff["network_diff"]["added"], ["8.8.8.8"])

        # Check file diff
        self.assertEqual(diff["file_diff"]["added"], ["/etc/shadow"])

        # Check signature diff
        self.assertEqual(diff["signature_diff"]["only_in_b"], ["sig2"])

        # Check verdict (should be divergent or suspicious given /etc/shadow and new network)
        self.assertIn(diff["verdict"], ["divergent", "suspicious"])

if __name__ == "__main__":
    unittest.main()
