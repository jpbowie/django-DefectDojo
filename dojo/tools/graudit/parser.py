import hashlib
from dojo.models import Finding


class GrauditParser(object):
    FINDING_TYPE_SEPERATOR = '##############################################\n'

    def get_scan_types(self):
        return ["Graudit Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Graudit (Grep) Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Graudit (Grep) Output"

    @classmethod
    def is_binary_match(self, line):
        return line.startswith('Binary file ')

    @classmethod
    def get_source_file(self, line):
        source_file = line.split(':', 2)[0]
        if source_file.startswith('Binary file'):
            source_file = source_file.replace(' matches', '')
            source_file = source_file.replace('Binary file ', '')
        return source_file

    @classmethod
    def get_source_line(self, line):
        parts = line.split(':', 2)

        if len(parts) < 2:
            return 1
        if parts[1].isdigit():
            return int(parts[1])
        return 1

    @classmethod
    def get_code_line(self, line):
        parts = line.split(':', 2)

        if len(parts) < 3:
            return ''

        return parts[2]

    def get_findings(self, filename, test):
        if filename is None:
            return

        dupes = dict()

        line = filename.readline()
        while line:
            if line == self.FINDING_TYPE_SEPERATOR:
                line = filename.readline()
                continue

            line_text = line
            if isinstance(line, bytes):
                line_text = line.decode('utf-8')

            dupe_key = hashlib.md5(line_text.encode('utf-8')).hexdigest()
            _source_file_path = self.get_source_file(line_text)
            _source_line_number = self.get_source_line(line_text)
            _source_line_code = self.get_code_line(line_text)
            finding_description = 'The following line(s) should be reviewed in the context that it\'s used: ' + \
                                  _source_line_code if not self.is_binary_match(line_text) else \
                'The binary contents of the file should be reviewed.'

            if dupe_key not in dupes:
                finding = Finding()
                finding.test = test
                finding.mitigation = ''
                finding.impact = ''
                finding.static_finding = True
                finding.dynamic_finding = False
                finding.severity = 'Info'
                finding.title = 'Graudit finding'
                finding.description = finding_description
                finding.file_path = _source_file_path
                finding.sourcefilepath = _source_file_path
                finding.sast_source_file_path = _source_file_path
                finding.line_number = _source_line_number
                finding.source_line = _source_line_number
                finding.sast_source_line = _source_line_number
                finding.date = test.target_start
                finding.is_mitigated = False
                finding.mitigated = None
                dupes[dupe_key] = finding

            line = filename.readline()
        return list(dupes.values())
