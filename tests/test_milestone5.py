"""Milestone 5 acceptance tests; cases also exported as expected-versus-actual matrix."""
import unittest
from tests.validation_cases import build_cases


class Milestone5AcceptanceTests(unittest.TestCase):
    def test_all_security_validation_cases(self):
        for case in build_cases():
            with self.subTest(category=case.category, scenario=case.name, input=case.input):
                self.assertEqual(case.actual, case.expected)


if __name__ == '__main__':
    unittest.main()
