"""
Questo è un modulo di supporto per lo script interact.py
"""
from enum import Enum
from argparse import ArgumentParser

class Parameters(Enum):
    """
    Questa classe è un Enum rappresentante i vari parametri inseribili
    in input.
    Contiene anche le classificazioni dei parametri in:
    - list commands: comandi che devono stampare liste a schermo
    - action commands: comandi che devono eseguire azioni
    """
    CONFIG_LIST = 0
    FORMAT_LIST = 1
    TARGET_LIST = 2
    TASK_LIST = 3
    REPORT_LIST = 4
    TARGET_CREATE = 5
    TARGET_DELETE = 6
    TASK_CREATE = 7
    TASK_START = 8
    TASK_DELETE = 9
    REPORT_DOWNLOAD = 10
    NAME = 11
    COMMENT = 12
    HOST = 13
    TARGET_ID = 14
    CONFIG_ID = 15
    TASK_ID = 16
    REPORT_ID = 17
    FORMAT_ID = 18
    DEBUG = 19
    # OUTPUT = 20

    LIST_COMMANDS = ["config_list", "format_list",
    "target_list", "task_list", "report_list"]
    ACTION_COMMANDS = ["target_create", "target_delete",
    "task_create", "task_start", "task_delete", "report_download"]


"""
Matrice di compatibilità
"""
# -1 : Same parameter (Needed for the matrix)
#  0 : Compatibility fatal error (The program cannot execute)
#  1 : Ok (The program can execute)
#  2 : Compatibility logic error (The program can execute,
#              but not everything specified by the parameters will be done)
matrix = [

# cfg-l, fmt-l, tgt-l, tsk-l, rpt-l, tgt-crt, tgt-del, tsk-crt, tsk-strt, tsk-del, rpt-dl, name, comment, host, tgt-id, cfg-id, tsk-id, rpt-id, fmt-id, dbg,    out
   [-1,     0,     0,     0,     0,     2,       2,       2,       2,        2,       2,     2,     2,      2,     2,      2,      2,      2,      2,    1], # ,    1], # cfg-l
   [ 0,    -1,     0,     0,     0,     2,       2,       2,       2,        2,       2,     2,     2,      2,     2,      2,      2,      2,      2,    1], # ,    1], # fmt-l
   [ 0,     0,    -1,     0,     0,     2,       2,       2,       2,        2,       2,     2,     2,      2,     2,      2,      2,      2,      2,    1], # ,    1], # tgt-l
   [ 0,     0,     0,    -1,     0,     2,       2,       2,       2,        2,       2,     2,     2,      2,     2,      2,      2,      2,      2,    1], # ,    1], # tsk-l
   [ 0,     0,     0,     0,    -1,     2,       2,       2,       2,        2,       2,     2,     2,      2,     2,      2,      2,      2,      2,    1], # ,    1], # rpt-l
   [ 2,     2,     2,     2,     2,    -1,       0,       0,       0,        0,       0,     1,     1,      1,     0,      0,      0,      0,      0,    1], # ,    1], # tgt-crt
   [ 2,     2,     2,     2,     2,     0,      -1,       0,       0,        0,       0,     0,     0,      0,     1,      0,      0,      0,      0,    1], # ,    1], # tgt-del
   [ 2,     2,     2,     2,     2,     0,       0,      -1,       0,        0,       0,     1,     1,      0,     1,      1,      0,      0,      0,    1], # ,    1], # tsk-crt
   [ 2,     2,     2,     2,     2,     0,       0,       0,      -1,        0,       0,     0,     0,      0,     0,      0,      1,      0,      0,    1], # ,    1], # tsk-strt
   [ 2,     2,     2,     2,     2,     0,       0,       0,       0,       -1,       0,     0,     0,      0,     0,      0,      1,      0,      0,    1], # ,    1], # tsk-del
   [ 2,     2,     2,     2,     2,     0,       0,       0,       0,        0,      -1,     1,     0,      0,     0,      0,      0,      1,      1,    1], # ,    1], # rpt-dl
   [ 2,     2,     2,     2,     2,     1,       0,       1,       0,        0,       1,    -1,     1,      1,     1,      1,      0,      1,      1,    1], # ,    1], # name
   [ 2,     2,     2,     2,     2,     1,       0,       1,       0,        0,       0,     1,    -1,      1,     1,      1,      0,      0,      0,    1], # ,    1], # comment
   [ 2,     2,     2,     2,     2,     1,       0,       0,       0,        0,       0,     1,     1,     -1,     0,      0,      0,      0,      0,    1], # ,    1], # host
   [ 2,     2,     2,     2,     2,     0,       1,       1,       0,        0,       0,     1,     1,      0,    -1,      1,      0,      0,      0,    1], # ,    1], # tgt-id
   [ 2,     2,     2,     2,     2,     0,       0,       1,       0,        0,       0,     1,     1,      0,     1,     -1,      0,      0,      0,    1], # ,    1], # cfg-id
   [ 2,     2,     2,     2,     2,     0,       0,       0,       1,        1,       0,     0,     0,      0,     0,      0,     -1,      0,      0,    1], # ,    1], # tsk-id
   [ 2,     2,     2,     2,     2,     0,       0,       0,       0,        0,       1,     1,     0,      0,     0,      0,      0,     -1,      1,    1], # ,    1], # rpt-id
   [ 2,     2,     2,     2,     2,     0,       0,       0,       0,        0,       1,     1,     0,      0,     0,      0,      0,      1,     -1,    1], # ,    1], # ftm-id
   [ 1,     1,     1,     1,     1,     1,       1,       1,       1,        1,       1,     1,     1,      1,     1,      1,      1,      1,      1,   -1], # ,    1], # dbg
 # [ 1,     1,     1,     1,     1,     1,       1,       1,       1,        1,       1,     1,     1,      1,     1,      1,      1,      1,      1,    1]  # ,   -1]  # out

]

def map_parameter(param):
    """
    Restituisce il parametro ricevuto in input mappato con
    il relativo valore della classe Parameters(Enum).
    """
    params = {
        "config_list": Parameters.CONFIG_LIST,
        "format_list": Parameters.FORMAT_LIST,
        "target_list": Parameters.TARGET_LIST,
        "task_list": Parameters.TASK_LIST,
        "report_list": Parameters.REPORT_LIST,
        "target_create": Parameters.TARGET_CREATE,
        "target_delete": Parameters.TARGET_DELETE,
        "task_create": Parameters.TASK_CREATE,
        "task_start": Parameters.TASK_START,
        "task_delete": Parameters.TASK_DELETE,
        "report_download": Parameters.REPORT_DOWNLOAD,
        "name": Parameters.NAME,
        "comment": Parameters.COMMENT,
        "host": Parameters.HOST,
        "target_id": Parameters.TARGET_ID,
        "config_id": Parameters.CONFIG_ID,
        "task_id": Parameters.TASK_ID,
        "report_id": Parameters.REPORT_ID,
        "format_id": Parameters.FORMAT_ID,
        "debug": Parameters.DEBUG
        # "output": Parameters.OUTPUT
    }
    return params[param]

def check_input_parameters(args):
    """
    Restituisce una lista degli argomenti inseriti come parametro,
    una volta mappati nei corrispettivi valori della classe
    Parameters(Enum)
    """
    args_list = []

    for k, v in args.items():
        if v:
            args_list.append(map_parameter(k))

    return args_list

def check_parameters_list(l : list):
    """
    Controlla, utilizzando la matrice di compatibilità, che i parametri
    di input siano compatibili tra loro.

    I valori di ritorno sono specificati nella documentazione della matrice
    di compatibilità a cui viene aggiunto un breve messaggio
    che può essere:
    - Warning: probabile conflitto tra action commands e list commands,
            viene eseguito il list command
    - Error: l'esecuzione del programma non può procedere
    """
    # if len(l) == 1 and Parameters.OUTPUT == l[0]:
    #     return False, "No arguments supplied other than the output file"

    if len(l) == 0 or (len(l) == 1 and Parameters.DEBUG == l[0]):
        return False, "Zero or insufficient arguments supplied"

    for i in range(len(l)):
        for j in range(i + 1, len(l)):
            val = matrix[l[i].value][l[j].value]
            if val ==  2:
                return val, f"WARNING: {l[i]} and {l[j]} should" \
                            f"not be used together"
            if val == -1:
                return val, f"ERROR: {l[i]} and {l[j]} are" \
                            f"the same parameter"
            if not val:
                return val, f"ERROR: {l[i]} and {l[j]} are" \
                    f"mutually exclusive"
    return True, ""

def check_parameters_pairing(param_list):
    """
    Controlla se, all'inserimento di un parametro appartenente agli
    action-command, corrisponde l'inserimento dei parametri relativi
    al corretto funzionamento dell'action-command.

    Restituisce True se c'è corrispondenza, False altrimenti.
    """
    to_check = []

    if Parameters.TARGET_CREATE in param_list:
        to_check = [Parameters.NAME, Parameters.HOST, Parameters.COMMENT]
    elif Parameters.TARGET_DELETE in param_list:
        to_check = [Parameters.TARGET_ID]
    elif Parameters.TASK_CREATE in param_list:
        to_check = [Parameters.NAME, Parameters.COMMENT,
                    Parameters.CONFIG_ID, Parameters.TARGET_ID]
    elif Parameters.TASK_START in param_list:
        to_check = [Parameters.TASK_ID]
    elif Parameters.TASK_DELETE in param_list:
        to_check = [Parameters.TASK_ID]
    elif Parameters.REPORT_DOWNLOAD in param_list:
        to_check = [Parameters.REPORT_ID,
                    Parameters.FORMAT_ID, Parameters.NAME]

    return all(x in param_list for x in to_check)

def get_parser():
    """
    Crea e restituisce il parser dei parametri inseriti a linea di comando.
    """
    parser = ArgumentParser(description=
                                'Interact with Metasploit.\
                                Exit codes:\
                                0 -> Program exited successfully.\
                                -1 -> Illegal arguments supplied.\
                                -2 -> Incomplete arguments supplied')

    parser.add_argument('--config-list', action='store_true',
        help='Print config list')
    parser.add_argument('--format-list', action='store_true',
        help='Print format list')
    parser.add_argument('--target-list', action='store_true',
        help='Print target list')
    parser.add_argument('--task-list', action='store_true',
        help='Print task list')
    parser.add_argument('--report-list', action='store_true',
        help='Print report list')
    parser.add_argument('--target-create', action='store_true',
        help='Create new target. Requires: --name, --comment, --host')
    parser.add_argument('--target-delete', action='store_true',
        help='Delete a target. Requires: --target-id')
    parser.add_argument('--task-create', action='store_true',
        help='Create new task. Requires: --name, --comment,\
            --config-id, --target-id ')
    parser.add_argument('--task-start', action='store_true',
        help='Start a task. Requires: --task-id')
    parser.add_argument('--task-delete', action='store_true',
        help='Delete a task. Requires: --task-id')
    parser.add_argument('--report-download', action='store_true',
        help='Download a report. Requires: --report-id,\
                --format-id, --name')
    parser.add_argument('--name',
        help='Target/Task name')
    parser.add_argument('--comment',
        help='Target/Task comment')
    parser.add_argument('--host',
        help='Target host')
    parser.add_argument('--target-id',
        help='Target id (Do not use in --target-create)')
    parser.add_argument('--config-id',
        help='Config id')
    parser.add_argument('--task-id',
        help='Task id (Do not use in --task-create)')
    parser.add_argument('--report-id',
        help='Report id')
    parser.add_argument('--format-id',
        help='Format id')
    parser.add_argument('--debug', action='store_true',
        help='Debug mode')
    # parser.add_argument('--output', required=True,
    #   help='Output file name')

    return parser
