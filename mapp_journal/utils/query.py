import os.path
from collections import Counter, defaultdict
from csv import DictReader
from pprint import pprint
import json
import argparse

try:
    import sqlite3
    import pandas as pd
    import pendulum
    from terminaltables import DoubleTable
except ModuleNotFoundError as error:
    print(error)
    exit(0)
except ImportError as error:
    print(error)
    exit(0)

def db_dump(dbfile, csvfile):
    global json_data
    '''Reads SQLiteDB file and exports data to a CSV document

    Returns: JSON (object) from SQLiteDB table
    '''
    if (os.path.isfile(dbfile)):
        connectObj = sqlite3.connect("db/mapp.db", check_same_thread=False)
        df = pd.read_sql_query("select * from mapplogs;", connectObj)
        df.to_csv(csvfile, mode='w', header=True, index=False, encoding='utf-8')
        connectObj.close()
    else:
        print('SQLite DB file not found!')
        exit(0)

    with open(csvfile, 'r') as csvObj:
        reader = list(DictReader(csvObj))

    if len(reader) > 0:
        json_data = json.loads(json.dumps(reader))
    else:
        print('No records found in database!\n')
        exit(0)

    return json_data


def get_statistics():
    flag_total = 0
    noinfo = []
    source_matches = defaultdict(list)
    mapp_sigable = defaultdict(list)
    mapp_nonsigable = defaultdict(list)
    itw_sigable = defaultdict(list)
    itw_nonsigable = defaultdict(list)

    try:
        # Validate input date strings initially
        if (pendulum.parse(args.fromdate) or pendulum.parse(args.enddate)) and (
                pendulum.parse(args.enddate) > pendulum.parse(args.fromdate)):
            for idx in json_data:
                if (pendulum.parse(idx['date']) >= pendulum.parse(args.fromdate)
                        and pendulum.parse(
                            idx['date']) <= pendulum.parse(args.enddate)):
                    flag_total += 1

                    if idx['source'] == 'No info':
                        source_matches[idx['source']].append(idx)
                        noinfo.append((idx['cve_id'], idx['vendor']))
                    elif idx['source'] == 'MAPP':
                        source_matches[idx['source']].append(idx)
                        if idx['sigable'] == 'Yes':
                            mapp_sigable[idx['sigable']].append((idx['cve_id'],
                                                                 idx['rules']))
                        elif idx['sigable'] == 'No':
                            mapp_nonsigable[idx['sigable']].append(
                                (idx['cve_id'], idx['reason'], idx['author']))
                    elif idx['source'] == 'ITW':
                        source_matches[idx['source']].append(idx)
                        if idx['sigable'] == 'Yes':
                            itw_sigable[idx['sigable']].append((idx['cve_id'],
                                                                idx['rules']))
                        elif idx['sigable'] == 'No':
                            itw_nonsigable[idx['sigable']].append(
                                (idx['cve_id'], idx['reason'], idx['author']))
        else:
            print('Invalid date range!\n')
            exit(0)
    except ValueError as error:
        print(error)
        exit(0)

    print('--[[ MAPP STATISTICS ]]--\n==========================')
    print('[*]Total CVEs:\t\t{}'.format(flag_total))
    print('[*]MAPP CVEs:')
    print('   - Sigable:\t\t{}'.format(len(mapp_sigable['Yes'])))
    print('   - Nonsigable:\t{}'.format(len(mapp_nonsigable['No'])))
    print('[*]ITW CVEs:')
    print('   - Sigable:\t\t{}'.format(len(itw_sigable['Yes'])))
    print('   - Nonsigable:\t{}'.format(len(itw_nonsigable['No'])))
    print('[*]No info CVEs:\t{}\n'.format(len(source_matches['No info'])))

    if len(mapp_sigable['Yes']) > 0 and (args.table == 'True' or args.table == 'true'):
        table = DoubleTable(title=' MAPP Sigable ', table_data=mapp_sigable['Yes'])
        table.inner_row_border = True
        table.inner_column_border = True
        table.justify_columns[0]='left'
        table.justify_columns[0]='center'
        print()
        print(table.table)
    if len(itw_sigable['Yes']) > 0 and (args.table == 'True' or args.table == 'true'):
        table = DoubleTable(title=' ITW Sigable ', table_data=itw_sigable['Yes'])
        table.inner_row_border = True
        table.inner_column_border = True
        table.justify_columns[0]='left'
        table.justify_columns[1]='center'
        print()
        print(table.table)
    if len(mapp_nonsigable['No']) > 0 and (args.table == 'True' or args.table == 'true'):
        table = DoubleTable(title=' MAPP Nonsigable ', table_data=mapp_nonsigable['No'])
        table.inner_row_border = True
        table.inner_column_border = True
        table.justify_columns[0]='center'
        table.justify_columns[1]='left'
        table.justify_columns[2]='center'
        print()
        print(table.table)
    if len(itw_nonsigable['No']) > 0 and (args.table == 'True' or args.table == 'true'):
        table = DoubleTable(title=' ITW Nonsigable ', table_data=itw_nonsigable['No'])
        table.inner_row_border = True
        table.inner_column_border = True
        table.justify_columns[0]='center'
        table.justify_columns[1]='left'
        table.justify_columns[2]='center'
        print()
        print(table.table)
    if len(noinfo) > 0 and (args.table == 'True' or args.table == 'true'):
        table = DoubleTable(title=' No info ', table_data=noinfo)
        table.inner_row_border = True
        table.inner_column_border = True
        table.justify_columns[0]='left'
        table.justify_columns[1]='left'
        print()
        print(table.table)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='MAPP Backlog Statistics Generator')
    parser.add_argument('-b', '--begin',
        dest='fromdate',
        type=str,
        required=True,
        help='Begin date (inclusive) in DD-MM-YYYY')
    parser.add_argument('-t', '--table',
        dest='table',
        required=False,
        type=str,
        default="False",
        help='Show tabular data for all categories')
    parser.add_argument('-e', '--end',
        dest='enddate',
        type=str,
        required=True,
        help='End date (inclusive) in DD-MM-YYYY')
    args = parser.parse_args()

    if(args):
        db_dump(dbfile='db/mapp.db', csvfile='db/output.csv')
        get_statistics()
