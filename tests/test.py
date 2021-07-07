import unittest
from click.testing import CliRunner
from surveyor import cli

###############################################################################
#                             HELP CENTER                                     #
###############################################################################

# Traceback to find exceptions:
# traceback.print_exception(*result.exc_info)

# Always use absolute path, ~/Documents doesn't work
###############################################################################


class SurveyorTest(unittest.TestCase):

    def setUp(self) -> None:

        self.deffile_name = './tests/surveyor_testing.json'
        self.output_name = './tests/surveyor-auto-unittesting.csv'
        # TODO make the credential.response file generic
        self.profile = 'demo'

        return super().setUp()

    # Everything below here works wonderfully....DONT BREAK THEM >:(
    def test_working_deffile_demo(self):
        runner = CliRunner()

        result = runner.invoke(cli, ['--deffile', self.deffile_name, '--profile', 'demo', '--output', self.output_name])

        self.assertIn(f"Processing definition file for {self.deffile_name}", result.output)

        self.assertEqual(result.exit_code, 0)


class FailureSurveyorTests(unittest.TestCase):

    def setUp(self) -> None:

        self.deffile_name = './tests/surveyor_testinsdfsdfsdfg.json'
        self.output_name = './tests/surveyor-auto-unittesting.csv'
        # TODO make the credential.response file generic
        self.profile = 'demo'

        return super().setUp()

    def test_no_argument_provided(self):
        runner = CliRunner()

        arguments = ["--deffile", "--profile", "--prefix", "--output", "--defdir", "--iocfile", "--ioctype", "--query", "--hostname", "--days", "--minutes", "--username"]

        for arg in arguments:
            with self.subTest(arg=arg):
                result = runner.invoke(cli, [arg])
                self.assertIn(f"Option '{arg}' requires an argument.\n", result.output)
                self.assertEqual(result.exit_code, 2)

    def test_not_supported_option(self):
        runner = CliRunner()

        arguments = ["--cs"]

        for arg in arguments:
            with self.subTest(arg=arg):
                result = runner.invoke(cli, [arg])
                self.assertIn(f"Error: No such option: {arg}", result.output)
                self.assertEqual(result.exit_code, 2)

    def test_incorrect_deffile(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['--deffile', self.deffile_name], catch_exceptions=False)

        self.assertIn("Error: The deffile doesn't exist. Please try again.", result.output)
        self.assertEqual(result.exit_code, 2)

    def test_invalid_argument(self):
        runner = CliRunner()
        result = runner.invoke(cli, ['--re6e56r5r6rt'])

        self.assertIn("Error: No such option:", result.output)
        self.assertEqual(result.exit_code, 2)


# class NumbersTest(unittest.TestCase):
#     def test_even(self):
#         """
#         Test that numbers between 0 and 5 are all even.
#         """
#         for i in range(0, 6):
#             with self.subTest(i=i):
#                 self.assertEqual(i % 2, 0)
#         self.assertEqual(1,1)
#     def test_other(self):
#         self.assertEqual(1, 2)


if __name__ == '__main__':
    unittest.main()
