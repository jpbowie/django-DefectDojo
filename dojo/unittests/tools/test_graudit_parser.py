from django.test import SimpleTestCase
from dojo.tools.graudit.parser import GrauditParser
from dojo.models import Test


class TestGrauditScannerParser(SimpleTestCase):
    def test_parse_file_with_one_finding(self):
        testfile = open("dojo/unittests/scans/graudit/one_finding.txt")
        parser = GrauditParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))

    def test_parse_file_with_one_finding(self):
        testfile = open("dojo/unittests/scans/graudit/multiple_findings.txt")
        parser = GrauditParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(2, len(findings))
        finding = findings[0]
        self.assertTrue(finding.static_finding)
        self.assertEqual('Info', finding.severity)
        self.assertEqual('Graudit finding', finding.title)
        self.assertEqual('The following line(s) should be reviewed in the context that it\'s used: Line of code with finding\n', finding.description)
        self.assertEqual('/pathtothefile/output.py', finding.sourcefilepath)
        self.assertEqual(23, finding.line_number)
        finding = findings[1]
        self.assertTrue(finding.static_finding)
        self.assertEqual('Info', finding.severity)
        self.assertEqual('Graudit finding', finding.title)
        self.assertEqual('The following line(s) should be reviewed in the context that it\'s used: Another Line of code with finding\n', finding.description)
        self.assertEqual('/pathtothefile/input.py', finding.sourcefilepath)
        self.assertEqual(92, finding.line_number)

    def test_parse_binary_finding(self):
        testfile = open('dojo/unittests/scans/graudit/binary_file_finding.txt')
        parser = GrauditParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual('/pathtothefile/output.db', finding.sourcefilepath)
        self.assertEqual('The binary contents of the file should be reviewed.', finding.description)
