import unittest
import os, sys

test_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(test_dir + "/../src")
sys.path.append(test_dir + "/../test")
# before reporter, env variables need to be set
import tests.lambda_env
import src.security_hub_reporter as reporter


class SecurityHubReporterTest(unittest.TestCase):

    def test_run_scan(self):
        reporter.lambda_handler(None, None)


if __name__ == '__main__':
    unittest.main()
