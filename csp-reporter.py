#!/usr/bin/env python3
"""
CSP Reporter

Copyright (c) 2020 leboncoin
MIT License
Written by Nicolas BEGUIER (nicolas.beguier@adevinta.com)

"""

# Standard library imports
import datetime
import json
import logging

# Third party library imports
from flask import Flask, jsonify, abort, make_response, request

# Own libraries
from utils.exception import is_exception
from utils.extra import extra_metadata
from utils.sqlite import SqliteCmd

# Debug
# from pdb import set_trace as st

VERSION = '%(prog)s 1.4.0'
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
logging.basicConfig(format='%(message)s')
LOGGER = logging.getLogger('csp-reporter')
SQL_TABLE = 'csp_reporter'

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

    if sql.sqlite_verify_entry(SQL_TABLE, blocked_uri_without_qp):
        sql.sqlite_update_lastseen(SQL_TABLE, blocked_uri_without_qp, csp_report['date'])
    else:
        sql.sqlite_insert(SQL_TABLE,
                          blocked_uri_without_qp,
                          csp_report['document-uri'],
                          csp_report['date'],
                          csp_report['date'])
    sql.sqlite_close()


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

    LOGGER.critical('[%s] %s -> %s',
                    csp_report['ua-browser'],
                    csp_report['document-uri'],
                    csp_report['blocked-uri'])

    LOGGER.critical(csp_report)

    update_database(csp_report)

    return make_response('', 204)


@APP.route('/health')
def health():
    result = {'name': 'csp-reporter', 'version': VERSION.split(' ')[1]}
    return make_response(json.dumps(result), 200)


if __name__ == '__main__':
    APP.run('0.0.0.0')
