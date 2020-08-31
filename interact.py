from pymetasploit3.msfrpc import MsfRpcClient
from pymetasploit3.msfconsole import MsfRpcConsole
from time import sleep
from sys import exit, stderr
from re import compile
from os import getcwd, kill, getpid
from signal import SIGTERM
from parameters import *
from functools import wraps
import inspect

def logger(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if DEBUG:
            params = []
            arg_spec = inspect.getfullargspec(function).args
            for arg_name, arg_value in zip(arg_spec, args):
                if type(arg_value) is str:
                    if len(arg_value) < 2 * LOG_SIZE:
                        params.append(arg_name + ":" + arg_value)
                    else:
                        params.append(arg_name + ":" + arg_value[:LOG_SIZE] + "  . . .  " + arg_value[-LOG_SIZE:])
                else:
                    params.append(arg_name + ":" + str(arg_value))

            func_signature = function.__name__ + '(' + ', '.join(params) + ')'

            print("LOGGER:\t" + func_signature)
            ret_value = function(*args, **kwargs)

            print("LOGGER:\t" + function.__name__ + "{}".format(
                " returned " + (str(ret_value) if ret_value is not None else "None")))
            return ret_value
        else:
            return function(*args, **kwargs)

    return wrapper

@logger
def exit_successfully(console):
    try:
        console.execute("openvas_disconnect")
        del(console)
        kill(getpid(), SIGTERM)
    except:
        print("Error while closing the program", file=stderr)

@logger
def read_console(console_data):
    data = console_data['data']
    str_data = data.rstrip().split('\n')
    if "[+] OpenVAS connection successful" in str_data and not any(PATTERN.match(line) for line in str_data):
        parts = data.partition("[-]")
        print(parts[0])
        if parts[1]:
            print("Done.")
        return
    if any('[+]' in string for string in str_data):
        parts = data.partition("[-]")
        print(parts[0])
        if parts[1]:
            print("Done.")
        exit_successfully(console)

@logger
def init_console(passwd):
    try:
        client = MsfRpcClient(passwd)
        console = MsfRpcConsole(client, cb=read_console)
        console.execute("load openvas")
        sleep(SLEEP_TIME)
        console.execute("openvas_connect admin admin 127.0.0.1 9390")
        return console
    except:
        return False

@logger
def print_lists(console, to_print):
    @logger
    def get_config_list(console):
        try:
            console.execute("openvas_config_list")
            sleep(SLEEP_TIME)
            return True
        except:
            return False

    @logger
    def get_format_list(console):
        try:
            console.execute("openvas_format_list")
            sleep(SLEEP_TIME)
            return True
        except:
            return False

    @logger
    def get_target_list(console):
        try:
            console.execute("openvas_target_list")
            sleep(SLEEP_TIME)
            return True
        except:
            return False

    @logger
    def get_task_list(console):
        try:
            console.execute("openvas_task_list")
            sleep(SLEEP_TIME)
            return True
        except:
            return False

    @logger
    def get_report_list(console):
        try:
            console.execute("openvas_report_list")
            sleep(SLEEP_TIME)
            return True
        except:
            return False

    if "config_list" in to_print:
        if not get_config_list(console):
            print("Error while getting config list", file=stderr)
            return False
    if "format_list" in to_print:
        if not get_format_list(console):
            print("Error while getting format list", file=stderr)
            return False
    if "target_list" in to_print:
        if not get_target_list(console):
            print("Error while getting target list", file=stderr)
            return False
    if "task_list"   in to_print:
        if not get_task_list(console):
            print("Error while getting task list", file=stderr)
            return False
    if "report_list" in to_print:
        if not get_report_list(console):
            print("Error while getting report list", file=stderr)
            return False
    return True
    
@logger
def get_action(args):
    @logger
    def target_create(console, args):
        try:
            console.execute(f'openvas_target_create "{args["name"]}" {args["host"]} "{args["comment"]}"')
            return True
        except:
            return False

    @logger
    def target_delete(console, args):
        try:
            console.execute(f'openvas_target_delete {args["target_id"]}')
            return True
        except:
            return False

    @logger
    def task_create(console, args):
        try:
            console.execute(f'openvas_task_create "{args["name"]}" "{args["comment"]}" {args["config_id"]} {args["target_id"]}')
            return True
        except:
            return False

    @logger
    def task_start(console, args):
        try:
            console.execute(f'openvas_task_start {args["task_id"]}')
            return True
        except:
            return False

    @logger
    def task_delete(console, args):
        try:
            console.execute(f'openvas_task_delete {args["task_id"]} ok')
            return True
        except:
            return False

    @logger
    def report_download(console, args):
        try:
            console.execute(f'openvas_report_download {args["report_id"]} {args["format_id"]} {args["path"]} "{args["name"]}"')
            return True
        except:
            return False

    function = None
    new_args = {}
    for k, v in args.items():
        if v:
            if "target_create" in k: return target_create, {"name": args["name"], "host": args["host"], "comment": args["comment"]}
            elif "target_delete" in k: return target_delete, {"target_id": args["target_id"]}
            elif "task_create" in k: return task_create, {"name": args["name"], "comment": args["comment"], "config_id": args["config_id"], "target_id": args["target_id"]}
            elif "task_start" in k: return task_start, {"task_id": args["task_id"]}
            elif "task_delete" in k: return task_delete, {"task_id": args["task_id"]}
            elif "report_download" in k: return report_download, {"report_id": args["report_id"], "format_id": args["format_id"], "path": PATH, "name": args["name"]}

LOG_SIZE = 40
MSF_PASSWD = "msf"
SLEEP_TIME = 0.5
SLEEP_BEFORE_EXITING_TIME = SLEEP_TIME * 15
PATH = getcwd() + r"/"
ID_REGEX = r"^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}"
PATTERN = compile(ID_REGEX)

global global_console_filter
global_console_filter = []
global global_console_status
global_console_status = False

parser = get_parser()
args = vars(parser.parse_args())

DEBUG = args["debug"]

param_list = check_input_parameters(args)
return_value, control = check_parameters_list(param_list)


if return_value == -1 or return_value == 0 or return_value is False:
    print(control, file=stderr)
    exit(-1)
if return_value == -2:
    print(control, file=stderr)
if not check_parameters_pairing(param_list):
    print("You didn't supply all the needed arguments for the command. Use --help.", file=stderr)
    exit(-2)

console = init_console(MSF_PASSWD)

if not console:
    print("Error initializing console.", file=stderr)
    exit(-3)

# OUTPUT_FILE = PATH + args["output"]

if any(args[x] for x in set(args.keys()).intersection(Parameters.LIST_COMMANDS.value)):
    to_print = []
    for k, v in args.items():
        if v and "list" in k:
            to_print.append(k)

    if not print_lists(console, to_print):
        print(f"Error in function: {print_lists.__name__}", file=stderr)

if any(args[x] for x in set(args.keys()).intersection(Parameters.ACTION_COMMANDS.value)):
    function, args = get_action(args)
    if not function(console, args):
        print(f"Error in function: {function.__name__}", file=stderr)
sleep(SLEEP_BEFORE_EXITING_TIME)
exit_successfully(console)
