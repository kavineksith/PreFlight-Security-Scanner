"""Unit tests for ReportGenerator."""

import pytest
import json
import csv
from pathlib import Path
from modules.reporter import ReportGenerator


class TestReportGenerator:
    def setup_method(self):
        pass

    def test_generate_html_creates_file(self, temp_output_dir, sample_report_data):
        gen = ReportGenerator(temp_output_dir)
        result = gen.generate_html(sample_report_data)
        assert result.exists()
        assert result.suffix == '.html'

    def test_generate_html_contains_target(self, temp_output_dir, sample_report_data):
        gen = ReportGenerator(temp_output_dir)
        result = gen.generate_html(sample_report_data)
        content = result.read_text()
        assert sample_report_data['target'] in content

    def test_generate_html_contains_findings(self, temp_output_dir, sample_report_data):
        gen = ReportGenerator(temp_output_dir)
        result = gen.generate_html(sample_report_data)
        content = result.read_text()
        for finding in sample_report_data['findings']:
            assert finding['title'] in content

    def test_generate_html_empty_findings(self, temp_output_dir):
        gen = ReportGenerator(temp_output_dir)
        data = {
            'target': 'http://test.com', 'scan_time': '2026-01-01T00:00:00',
            'duration_seconds': 1.0, 'authenticated': False,
            'total_findings': 0, 'findings': []
        }
        result = gen.generate_html(data)
        assert result.exists()

    def test_generate_json_creates_file(self, temp_output_dir, sample_report_data):
        gen = ReportGenerator(temp_output_dir)
        result = gen.generate_json(sample_report_data)
        assert result.exists()
        assert result.suffix == '.json'

    def test_generate_json_roundtrip(self, temp_output_dir, sample_report_data):
        gen = ReportGenerator(temp_output_dir)
        result = gen.generate_json(sample_report_data)
        with open(result) as f:
            data = json.load(f)
        assert data['target'] == sample_report_data['target']
        assert len(data['findings']) == len(sample_report_data['findings'])

    def test_generate_csv_creates_file(self, temp_output_dir, sample_findings):
        gen = ReportGenerator(temp_output_dir)
        result = gen.generate_csv(sample_findings)
        assert result.exists()
        assert result.suffix == '.csv'

    def test_generate_csv_row_count(self, temp_output_dir, sample_findings):
        gen = ReportGenerator(temp_output_dir)
        result = gen.generate_csv(sample_findings)
        with open(result, newline='') as f:
            reader = csv.reader(f)
            rows = list(reader)
        assert len(rows) == len(sample_findings) + 1  # +1 for header

    def test_generate_csv_empty(self, temp_output_dir):
        gen = ReportGenerator(temp_output_dir)
        result = gen.generate_csv([])
        assert result.exists()

    def test_generate_console_summary_no_crash(self, temp_output_dir, sample_report_data, capsys):
        gen = ReportGenerator(temp_output_dir)
        gen.generate_console_summary(sample_report_data)
        captured = capsys.readouterr()
        assert 'SCAN SUMMARY' in captured.out
