import json

import pandas as pd

import security_scanner as ss


def _setup_fake_checks(monkeypatch):
    fake_checks = {
        'C1': {'priority': 'High', 'desc': 'First control'},
        'C2': {'priority': 'Low', 'desc': 'Second control'},
    }
    fake_type_checks = {
        'web': ['C1', 'C2'],
        'other': [],
    }
    monkeypatch.setattr(ss, 'CHECKS', fake_checks)
    monkeypatch.setattr(ss, 'TYPE_CHECKS', fake_type_checks)
    monkeypatch.setattr(ss, 'STANDARDS', {})
    return fake_checks, fake_type_checks


def test_status_labels_are_only_allowed_set():
    allowed = {
        ss.STATUS_PASS,
        ss.STATUS_FAIL,
        ss.STATUS_NOT_TESTED,
        ss.STATUS_NOT_APPLICABLE,
        ss.STATUS_ERROR,
    }
    assert set(ss.STATUS_LABELS.keys()) == allowed
    assert set(ss.STATUS_LABELS.values()) == {'Pass', 'Fail', 'Not Tested', 'Not Applicable', 'Error'}


def test_not_applicable_only_when_not_relevant(monkeypatch):
    _setup_fake_checks(monkeypatch)
    check_results = {}
    completed = ss.complete_check_results('web', check_results)
    assert completed['C1'].status == ss.STATUS_NOT_TESTED
    assert completed['C2'].status == ss.STATUS_NOT_TESTED

    completed_other = ss.complete_check_results('other', {})
    assert completed_other['C1'].status == ss.STATUS_NOT_APPLICABLE
    assert completed_other['C1'].reason_code == 'NOT_APPLICABLE_BY_TYPE'
    assert completed_other['C2'].status == ss.STATUS_NOT_APPLICABLE


def test_unimplemented_controls_become_not_tested_not_not_applicable(monkeypatch):
    _setup_fake_checks(monkeypatch)
    check_results = {}
    completed = ss.complete_check_results('web', check_results)
    for cid in ['C1', 'C2']:
        assert completed[cid].status == ss.STATUS_NOT_TESTED
        assert completed[cid].reason_code == 'NOT_IMPLEMENTED'


def test_coverage_summary_counts_consistent_with_all_parameters(monkeypatch, tmp_path):
    _setup_fake_checks(monkeypatch)

    results_list = [
        {
            'Subdomain': 'a.example',
            'Type': 'web',
            'Scan_Success': True,
            'Total_Score': 50,
            'Risk_Rating': 'Low',
            'check_results': {
                'C1': ss.set_status('C1', ss.STATUS_PASS),
                'C2': ss.set_status('C2', ss.STATUS_FAIL),
            },
            'relevant_checks': ['C1', 'C2'],
        },
        {
            'Subdomain': 'b.example',
            'Type': 'web',
            'Scan_Success': False,
            'Total_Score': 10,
            'Risk_Rating': 'High',
            'check_results': {
                'C1': ss.set_status('C1', ss.STATUS_ERROR, 'HTTP_TIMEOUT'),
                'C2': ss.set_status('C2', ss.STATUS_NOT_TESTED, 'NOT_IMPLEMENTED'),
            },
            'relevant_checks': ['C1', 'C2'],
        },
    ]

    output = tmp_path / 'report.xlsx'
    ss.build_reports('example.com', results_list, discovery_stats=None, technologies_detected=None, output_path=output)

    all_params = pd.read_excel(output, sheet_name='All Parameters')
    coverage = pd.read_excel(output, sheet_name='Parameter Coverage Summary')

    def derive_counts(df, control):
        status_counts = df[control].value_counts().to_dict()
        total = len(df)
        return {
            'total': total,
            'pass': status_counts.get('Pass', 0),
            'fail': status_counts.get('Fail', 0),
            'error': status_counts.get('Error', 0),
            'not_tested': status_counts.get('Not Tested', 0),
            'not_applicable': status_counts.get('Not Applicable', 0),
        }

    c1_counts = derive_counts(all_params, 'C1')
    c2_counts = derive_counts(all_params, 'C2')

    c1_row = coverage[coverage['Control_ID'] == 'C1'].iloc[0]
    c2_row = coverage[coverage['Control_ID'] == 'C2'].iloc[0]

    assert c1_row['Total_Subdomains'] == c1_counts['total']
    assert c1_row['Relevant_Subdomains'] == c1_counts['total'] - c1_counts['not_applicable']
    assert c1_row['Passed'] == c1_counts['pass']
    assert c1_row['Failed'] == c1_counts['fail']
    assert c1_row['Not_Tested'] == c1_counts['not_tested']
    assert c1_row['Error'] == c1_counts['error']
    assert c1_row['Not_Applicable'] == c1_counts['not_applicable']

    assert c2_row['Total_Subdomains'] == c2_counts['total']
    assert c2_row['Relevant_Subdomains'] == c2_counts['total'] - c2_counts['not_applicable']
    assert c2_row['Passed'] == c2_counts['pass']
    assert c2_row['Failed'] == c2_counts['fail']
    assert c2_row['Not_Tested'] == c2_counts['not_tested']
    assert c2_row['Error'] == c2_counts['error']
    assert c2_row['Not_Applicable'] == c2_counts['not_applicable']