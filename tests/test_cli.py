import unittest
from blackboxjail.cli import build_parser


class CliTests(unittest.TestCase):
    def test_run_command_parsing(self):
        args = build_parser().parse_args(["run", "--timeout", "5", "--", "echo", "hello"])
        self.assertEqual(args.subcommand, "run")
        self.assertEqual(args.timeout, 5)
        self.assertEqual(args.command, ["--", "echo", "hello"])

    def test_resource_controls_parse(self):
        args = build_parser().parse_args(["run", "--cgroups", "required", "--max-processes", "24",
                                          "--max-file-mb", "32", "--no-seccomp", "--", "/bin/true"])
        self.assertEqual(args.cgroups, "required")
        self.assertEqual(args.max_processes, 24)
        self.assertTrue(args.no_seccomp)
        self.assertEqual(args.max_file_mb, 32)

    def test_audit_benchmark_and_measure_commands_exist(self):
        parser = build_parser()
        self.assertEqual(parser.parse_args(["audit"]).subcommand, "audit")
        self.assertEqual(parser.parse_args(["benchmark"]).subcommand, "benchmark")
        measure = parser.parse_args(["measure", "--iterations", "5", "--cgroups", "off"])
        self.assertEqual(measure.subcommand, "measure")
        self.assertEqual(measure.iterations, 5)

    def test_inspect_command_supports_run_id_and_raw(self):
        args = build_parser().parse_args(["inspect", "--run-id", "abc", "--raw"])
        self.assertEqual(args.subcommand, "inspect")
        self.assertEqual(args.run_id, "abc")
        self.assertTrue(args.raw)

    def test_network_can_be_explicitly_disabled(self):
        args = build_parser().parse_args(["run", "--no-network", "--", "/bin/true"])
        self.assertFalse(args.network)


if __name__ == "__main__":
    unittest.main()
