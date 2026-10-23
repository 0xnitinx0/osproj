import os
import sys
import unittest

from blackboxjail.monitor import process_tree_metrics


class MonitorTests(unittest.TestCase):
    def test_current_process_is_counted(self):
        if not os.path.exists("/proc/self/stat"):
            self.skipTest("Linux /proc is required for process-tree sampling")
        result = process_tree_metrics(os.getpid())
        self.assertGreaterEqual(result["process_count"], 1)
        self.assertGreaterEqual(result["rss_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
