#!/usr/bin/env python3
"""
CSP Reporter

Copyright (c) 2020-2021 leboncoin
MIT License
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)

"""

# Standard library imports
import datetime
import json
import logging

# Third party library imports
from flask import Flask, jsonify, abort, make_response, request
from patrowl4py.api import PatrowlManagerApi

# Own libraries
from utils.exception import is_exception
from utils.extra import extra_metadata
from utils.patrowl import add_asset, get_assets, add_in_assetgroup, add_finding, get_findings
from utils.sqlite import SqliteCmd
import settings

# Debug
# from pdb import set_trace as st

VERSION = '%(prog)s 1.7.1'
APP = Flask(__name__)
REPORT_PROPERTIES = [
    'blocked-uri',
    'column-number',
    'date',
    'document-uri',
    'effective-directive',
    'line-number',
    'original-policy',
    'referrer',
    'script-sample',
    'status-code',
    'ua-browser',
    'ua-platform',
    'violated-directive',
]
UA_MAPPING = {
    'chrome': 'UAChrome',
    'edge': 'UAEdge',
    'firefox': 'UAFirefox',
    'safari': 'UASafari',
    'other': 'UAOther'
}
logging.basicConfig(format='%(message)s')
LOGGER = logging.getLogger('csp-reporter')
SQL_TABLE = 'csp_reporter'

if settings.enable_patrowl:
    PATROWL_API = PatrowlManagerApi(
        url=settings.patrowl_endpoint,
        auth_token=settings.patrowl_api_token
    )

def generate_report(data):
    """
    Generate a valid csp report from request, and an HTTP status
    """
    csp_report = dict()
    for prop in REPORT_PROPERTIES:
        csp_report[prop] = ''

    try:
        csp_report_data = json.loads(data)
    except json.decoder.JSONDecodeError:
        return None, 400
    except:
        return None, 400

    if not 'csp-report' in csp_report_data:
        return None, 400
    csp_report_data = csp_report_data['csp-report']

    if is_exception(csp_report_data):
        return None, 204

    for key in csp_report_data:
        if key in REPORT_PROPERTIES:
            csp_report[key] = csp_report_data[key]
    csp_report['date'] = datetime.datetime.now()
    csp_report['ua-browser'] = request.user_agent.browser
    csp_report['ua-platform'] = request.user_agent.platform

    return csp_report, 204


def update_database(csp_report):
    """
    Update the SQLite database
    """
    sql = SqliteCmd('csp_reporter.sqlite')
    sql.sqlite_create_table(SQL_TABLE)

    blocked_uri_without_qp = csp_report['blocked-uri'].split('?')[0]

    if sql.sqlite_verify_entry(SQL_TABLE, blocked_uri_without_qp, csp_report['violated-directive']):
        sql.sqlite_update_lastseen(SQL_TABLE, blocked_uri_without_qp, csp_report['violated-directive'], csp_report['date'])
    else:
        sql.sqlite_insert(SQL_TABLE,
                          blocked_uri_without_qp,
                          csp_report['violated-directive'],
                          csp_report['document-uri'],
                          csp_report['date'],
                          csp_report['date'],
                          csp_report['column-number'],
                          csp_report['line-number'],
                          csp_report['referrer'],
                          csp_report['script-sample'])

    if csp_report['ua-browser'] in UA_MAPPING:
        sql.sqlite_increase_ua(SQL_TABLE, blocked_uri_without_qp, csp_report['violated-directive'], UA_MAPPING[csp_report['ua-browser']])
    else:
        sql.sqlite_increase_ua(SQL_TABLE, blocked_uri_without_qp, csp_report['violated-directive'], UA_MAPPING['other'])

    sql.sqlite_close()


def update_patrowl(csp_report):
    """
    Update the Patrowl database
    """
    assets = get_assets(PATROWL_API, settings.patrowl_asset_group)
    new_asset = True
    asset_id = None
    asset_url = csp_report['blocked-uri'].split('?')[0]
    asset_patrowl_name = asset_url\
        .replace('https://', '')\
        .replace('http://', '')\
        .split('/')[0]
    for asset in assets:
        if asset['name'] == asset_patrowl_name:
            new_asset = False
            asset_id = asset['id']
            continue
    if new_asset:
        LOGGER.warning('Add a new asset: %s', asset_patrowl_name)
        created_asset = add_asset(
            PATROWL_API,
            asset_patrowl_name,
            asset_patrowl_name)
        if not created_asset or 'id' not in created_asset:
            LOGGER.critical('Error during asset %s creation...', asset_patrowl_name)
            return False
        asset_id = created_asset['id']
        add_in_assetgroup(
            PATROWL_API,
            settings.patrowl_asset_group,
            asset_id)
    if csp_report['ua-browser'] not in UA_MAPPING:
        ua_browser = UA_MAPPING['other']
    else:
        ua_browser = UA_MAPPING[csp_report['ua-browser']]
    findings = get_findings(PATROWL_API, asset_id)
    new_finding = True
    finding_title = f'[{csp_report["effective-directive"]}][{ua_browser}] {asset_url}'
    for finding in findings:
        if finding['title'] == finding_title:
            new_finding = False
    if new_finding:
        LOGGER.warning('Add finding: %s for asset %s',
            finding_title,
            asset_patrowl_name)
        add_finding(
            PATROWL_API,
            asset_id,
            finding_title,
            str(csp_report),
            'medium')
    return True


@APP.errorhandler(400)
def error_400(error):
    return make_response(jsonify({
        'error': str(error)
    }), 400)


@APP.errorhandler(404)
def error_404(error):
    return make_response(jsonify({
        'error': str(error)
    }), 404)


@APP.errorhandler(405)
def error_405(error):
    return make_response(jsonify({
        'error': str(error),
    }), 405)


@APP.route('/api/csp-report/v1/report/', methods=['POST'])
def csp_receiver():
    """
    POST report
    """
    if request.content_type != 'application/csp-report':
        abort(400)

    csp_report, status = generate_report(request.data)

    if csp_report is None and status in [400, 404, 405]:
        abort(status)
    elif csp_report is None and status == 204:
        return make_response('', 204)

    csp_report = extra_metadata(csp_report, request)

    LOGGER.debug('[%s][%s] %s -> %s',
                    csp_report['violated-directive'],
                    csp_report['ua-browser'],
                    csp_report['document-uri'],
                    csp_report['blocked-uri'])

    LOGGER.debug(csp_report)

    update_database(csp_report)

    if settings.enable_patrowl:
        update_patrowl(csp_report)

    return make_response('', 204)


@APP.route('/health')
def health():
    result = {'name': 'csp-reporter', 'version': VERSION.split(' ')[1]}
    return make_response(json.dumps(result), 200)


if __name__ == '__main__':
    APP.run('0.0.0.0', port=80)
