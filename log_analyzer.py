#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''script for parsing NGINX logs'''

from argparse import ArgumentParser
import re
import gzip
import json
import os
import sys
import logging
from datetime import datetime
from string import Template
from time import time
from collections import defaultdict, namedtuple

DEBUG = True

CONFIG = {
    'REPORT_SIZE': 100,
    'REPORT_DIR': './reports',
    'MONITORING_LOG': False,
    'TS_DIR': '/var/tmp/log_analyzer.ts',
    'LOG_DIR': './log',
    'PARSED_PERCENT': 50
}

HTML_TEMPLATE_PATH = './reports/report.html'
DEFAULT_CONFIG_DESTINATION = './log_analyzer.conf'


def read_config_file(config, config_destination):
    '''Read configuration file, if it exists.
    Parse configuration and replace defaults.'''

    try:
        with open(config_destination) as config_file:
            config_form_file = json.load(config_file)
            config.update(config_form_file)
            return config
    except:
        raise IOError('FATAL! Cannot read CONFIG file.')


def find_log_file(log_files, log_dir):
    '''find the newest log file'''

    log_files = sorted(log_files, reverse=True)

    new_log_file = ''
    for f in log_files:
        if re.match(r'nginx-access-ui.log-\d{8}(.gz)?', f):
            new_log_file = f
            date = re.findall(r'\d{8}', f)[0]
            break
    if not new_log_file:
        logging.error('There are no log files in the directory')
        return False
    log_file_path = os.path.join(log_dir, new_log_file)

    Logfile = namedtuple('Logfile', ['path', 'date'])
    actual_log_file = Logfile(log_file_path, date)

    return actual_log_file


def if_there_are_a_report(report_dir, date):
    '''check if the current report already exists'''
    report_name = 'report-{}.html'.format(date)
    report_file = os.path.join(report_dir, report_name)
    if os.path.exists(report_file):
        logging.info('Your report is already in the report folder')
        return True
    else:
        return False


def read_log_file(log_file_destination):
    """open and iterate read log file line by line"""

    if log_file_destination.endswith(".gz"):
        log_file = gzip.open(log_file_destination, 'rb')
    else:
        log_file = open(log_file_destination)
    for line in log_file:
        if line:
            yield line
    log_file.close()


def parse_line(line):
    '''parse line in the log by regular expressions'''

    address_pattern = r'\B(?:/(?:[\w?=_&-]+))+'  # address
    time_pattern = r'\d+\.\d+$'  # time
    match_address = re.findall(address_pattern, line)
    if match_address:
        return (re.findall(address_pattern, line)[0],
                re.findall(time_pattern, line)[0])
    return False


def median(lst):
    '''count the median of the list items'''

    n = len(lst)
    if n < 1:
        return None
    if n % 2 == 1:
        return sorted(lst)[n//2]
    return sum(sorted(lst)[n//2-1:n//2+1])/2.0


def ts_update(ts_dir):
    '''update ts-file after success'''

    with open(ts_dir, 'w') as ts_file:
        ts_file.write(str(time())[:10])


def aggregate_logs(log_iterator, parsed_persent_from_config):
    '''parse and aggregate all logs from file'''

    logging.info('START aggregate raw data')
    log_statistics = defaultdict(list)
    log_statistics['count_all'] = 0
    log_statistics['time_all'] = 0
    processed = 0

    for line in log_iterator:
        processed += 1
        if parse_line(line):
            url, time_opened = parse_line(line)
            log_statistics['count_all'] += 1
            log_statistics['time_all'] += float(time_opened)
        else:
            continue
        log_statistics[url].append(float(time_opened))

        if processed % 10000 == 0:
            logging.info('OK. Processed {} lines'.format(processed))

    parsed_percent = log_statistics['count_all']*100/processed
    logging.info('INFO: {} percent of lines in log \
                  are parsed'.format(parsed_percent))
    if parsed_percent < parsed_persent_from_config:
        raise RuntimeError('Fatal problem in log file')

    logging.info('START recalculate aggregated table')

    result_table = []
    processed = 0
    for url in log_statistics:
        processed += 1
        if url in ['count_all', 'time_all']:
            continue
        times = log_statistics[url]
        counts = len(log_statistics[url])
        line = {
            "count": counts,
            "time_avg": sum(times)/counts,
            "time_max": max(times),
            "time_sum": sum(times),
            "url": url,
            "time_med": median(times),
            "time_perc": sum(times)*100/log_statistics['time_all'],
            "count_perc": counts*100/log_statistics['count_all']
        }
        if processed % 10000 == 0:
            logging.info('OK. Calculated {} lines'.format(processed))
        result_table.append(line)

    return result_table


def generate_report_from_template(result_table, destination, report_size):
    '''generate HTML report file'''
    
    sorted_result_json = json.dumps(sorted(result_table,
                                    key=lambda k: k['time_sum'], 
                                    reverse=True)[:report_size])
    logging.info('JSON table is ready')

    with open(HTML_TEMPLATE_PATH, 'r') as html_template:
        template_data = Template(html_template.read())
    report_data = template_data.safe_substitute(table_json=sorted_result_json)
    with open(destination, 'w') as html_report:
        html_report.write(report_data)
    logging.info('SUCCESS Report is precessed: {}'.format(destination))


def main(config):
    '''main function to rule them all'''

    # read all files in directory and check that logs exists
    try:
        log_files = os.listdir(CONFIG['LOG_DIR'])
    except OSError:
        logging.error('There are no directory for logs or reports. \
                       Please, add some in config file.')
        sys.exit()

    # find log file and exit if it exist
    actual_log_file = find_log_file(log_files, config['LOG_DIR'])

    if not actual_log_file:
        sys.exit()

    # check if report exists
    if if_there_are_a_report(config['REPORT_DIR'], actual_log_file.date):
        sys.exit()

    # parsing and aggregate raw data from log file
    log_iterator = read_log_file(actual_log_file.path)
    result_table = aggregate_logs(log_iterator, config['PARSED_PERCENT'])

    # generate report from template
    new_report_name = '{}/report-{}.html'.format(config['REPORT_DIR'], 
                                                 datetime.today()
                                                 .strftime('%Y%m%d'))
    generate_report_from_template(result_table,
                                  new_report_name, config['REPORT_SIZE'])

    # ts update
    ts_update(config['TS_DIR'])


if __name__ == "__main__":

    # read --config flag from comand line
    argp = ArgumentParser()
    argp.add_argument("--config", dest='config_file',
                      default=DEFAULT_CONFIG_DESTINATION, type=str)

    config_destination = argp.parse_args().config_file

    # read configuration
    config = read_config_file(CONFIG, config_destination)

    # configurate and start logging
    logging.basicConfig(filename=config['MONITORING_LOG'] or None,
                        level=logging.DEBUG if DEBUG else logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s',
                        datefmt='%Y.%m.%d %H:%M:%S')

    logging.info('START logging')

    try:
        main(config=config)
    except Exception:
        logging.exception('ERROR')
