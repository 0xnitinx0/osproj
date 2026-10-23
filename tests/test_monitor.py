import os
import sys
import unittest

from blackboxjail.monitor import process_tree_metrics


class MonitorTests(unittest.TestCase):
    def test_current_process_is_counted(self):
        result = process_tree_metrics(os.getpid())
        self.assertGreaterEqual(result["process_count"], 1)
        self.assertGreaterEqual(result["rss_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
