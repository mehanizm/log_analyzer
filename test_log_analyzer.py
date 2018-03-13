#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import log_analyzer


class LogAnalyzerTests(unittest.TestCase):
    
    def test_median(self):
        # медиана для четного количества
        self.assertEqual(log_analyzer.median([1, 2, 3, 4, 5]), 3)
        # медиана для нечетного количества
        self.assertEqual(log_analyzer.median([1, 2, 4, 5]), 3)
        # медиана для одного значения
        self.assertEqual(log_analyzer.median([1]), 1)

    def test_parse_line(self):
        line_1 = '1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300]\
                  "GET /api/v2/banner/25019354 HTTP/1.1" 200 927 "-"\
                  "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5"\
                  "-" "1498697422-2190034393-4708-9752759" "dc7161be3" 0.390'
        line_2 = '1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] "GET 200 927\
                  "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1\
                  GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752759"\
                  "dc7161be3'
        # найти и адрес и время
        self.assertEqual(log_analyzer.parse_line(line_1), 
                         ('/api/v2/banner/25019354', '0.390'))
        # когда в строке ничего нет
        self.assertEqual(log_analyzer.parse_line(line_2), False)

    def test_aggregate_logs_ok(self):
        log_list = [
            '1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300]\
            "GET /api/v2/banner/25019354 HTTP/1.1" 200 927 \
            "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 \
            GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752759"\
            "dc7161be3" 0.390'
        ]
        result = [
            {
                "count": 1,
                "time_avg": 0.390,
                "time_max": 0.390,
                "time_sum": 0.390,
                "url": '/api/v2/banner/25019354',
                "time_med": 0.390,
                "time_perc": 100,
                "count_perc": 100
            }
        ]

        self.assertEqual(log_analyzer.aggregate_logs(log_list, 50), result)
    
    def test_aggregate_logs_not_ok(self):

        log_list_none = [
            '1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300]\
            "GET P/1.1" 200 927 "-" "Lynx/2.8.8dev.9\
            libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5"\
            "-" "1498697422-2190034393-4708-9752759" "dc7161b'
        ]
        with self.assertRaises(RuntimeError):
            log_analyzer.aggregate_logs(log_list_none, 50)

    def test_find_log_file_exist(self):
        log_files_true = [
            ';lkdjfa',
            'dfasdf',
            'nginx-access-ui.log-20170630',
            'nginx-access-ui.log-20170530',
            'nginx-access-ui.log-20170629.gz'
        ]
        self.assertEqual(log_analyzer.find_log_file(log_files_true,
                                                    'directory').path,
                         'directory/nginx-access-ui.log-20170630')

    def test_find_log_file_not_exist(self):
        log_files_false = [
            ';lkdjfa',
            'dfasdf',
            'fdasf'
        ]
        self.assertEqual(log_analyzer.find_log_file(log_files_false, 
                         'directory'), False)

    def test_if_there_are_a_report_true(self):
        self.assertEqual(log_analyzer.if_there_are_a_report('./test_reports',
                         '01010101'), True)

    def test_if_there_are_a_report_false(self):
        self.assertEqual(log_analyzer.if_there_are_a_report('./test_reports',
                         '01020101'), False)

if __name__ == "__main__":
    unittest.main()
