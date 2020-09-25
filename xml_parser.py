"""
Questo modulo si occupa di filtrare il report in formato XML generato
dallascansione del target ottenuto dall'esecuzione di interact.py
"""
from xml.etree.ElementTree import parse
from os.path import dirname
from argparse import ArgumentParser
from datetime import datetime
from json import dumps
from re import compile


def get_parser():
    """
    Crea e restituisce il parser dei parametri inseriti a linea di comando.
    """
    parser = ArgumentParser(
        description='Filter something out of an XML'
                    'report created by OpenVAS.')
    parser.add_argument('--all', action='store_true',
        help='Add everything into the report')
    parser.add_argument('--owner', action='store_true',
        help='Add owner to the report')
    parser.add_argument('--hosts-number', action='store_true',
        help='Add hosts number to the report')
    parser.add_argument('--vulns-number', action='store_true',
        help='Add vulns number to the report')
    parser.add_argument('--os-number', action='store_true',
        help='Add os number to the report')
    parser.add_argument('--apps', action='store_true',
        help='Add apps to the report')
    parser.add_argument('--ssl-certs', action='store_true',
        help='Add ssl certs to the report')
    parser.add_argument('--timestamp', action='store_true',
        help='Add timestamp to the report')
    parser.add_argument('--tasks', action='store_true',
        help='Add tasks to the report')
    parser.add_argument('--ports', action='store_true',
        help='Add ports to the report')
    parser.add_argument('--results', action='store_true',
        help='Add results to the report')
    parser.add_argument('--results-count', action='store_true',
        help='Add results count to the report')
    parser.add_argument('--details', action='store_true',
        help='Add details to the report')
    parser.add_argument('--errors', action='store_true',
        help='Add errors to the report')
    parser.add_argument('--input', required=True,
        help='Input file')

    return parser


def get_indexes(root) -> dict:
    """
    Restituisce un dizionario contenente un'indicizzazione della
    lista dei sotto-nodi del nodo (XML) passato come parametro.
    """
    index_dict = {}
    for index, name in enumerate(root):
        index_dict[name.tag] = index
    return index_dict


def create_task_dict(task) -> dict:
    """
    Restituisce un dizionario contenente le informazioni
    riguardanti il contenuto del nodo task (XML).
    I campi filtrati sono:
    - id;
    - nome;
    - commento;
    - target-id.
    """
    task_dict = {}
    task_dict["id"] = task.attrib.get("id")
    task_dict[task[0].tag] = task[0].text
    task_dict[task[1].tag] = task[1].text
    task_dict[task[2].tag + " id"] = task[2].attrib.get("id")
    return task_dict


def create_ports_json(ports, column_names) -> dict:
    """
    Crea e restituisce un dizionario contenente le informazioni
    riguardanti il contenuto del nodo ports (XML).
    I campi filtrati sono:
    - port (porta);
    - severity (gravità);
    - threat (minaccia).
    """

    def check_ip(element) -> bool:
        """
        Funzione necessaria per compatibilità con diversi tipi
        di scansioni, le quali generano report con piccole differenze.

        Restituisce True nel caso in cui l'elemento passato
        come parametro è un indirizzo ip, False altrimenti
        """
        regex = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])" \
                r"\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        return True if compile(regex).match(element) else False

    json_ports = {}

    # Per ogni elemento presente nel nodo ports (XML):
    for element in ports:

        # Ottieni host, port, severity e threat dall'elemento
        host, port, severity, threat = \
            [text for text in element.itertext()]

        # Stabilisci come scrivere i file nel dizionario
        if not check_ip(host):
            host, port = port, host
        if host not in json_ports:
            json_ports[host] = []

        # Scrivi i file nel dizionario ed aggiungilo alle informazioni
        # da restituire in output
        json_element = {column_names[1]: port,
                        column_names[2]: severity,
                        column_names[3]: threat}
        json_ports[host].append(json_element)

    return json_ports


def create_result_json(results, column_names) -> dict:
    """
    Crea e restituisce un dizionario contenente le informazioni
    riguardanti il contenuto del nodo results (XML).
    I campi filtrati sono:
    - port (porta)
    - nvt (Network Vulnerability Test)
    - threat (minaccia)
    - severity (gravità)
    - detection (risultato della scansione)
    - qod (Quality of Detection [0 - 100]%)
    - description (descrizione)
    """

    def filter_detection(detection):
        """
        Crea e restituisce il dizionario relativo all'intero nodo
        detection (XML).
        """
        detect_filtered = {}

        # Se il nodo esiste
        if detection[0].attrib.get("id"):

            # Aggiungi ogni elemento al dizionario
            for element in detection[0]:
                for name, value in element:
                    detect_filtered[name.text] = value.text

        return detect_filtered

    def get_tag_and_text_in_xml_tag(root) -> dict:
        """
        Crea e restituisce un dizionario contenente tutti i sotto-nodi
        del nodo inserito in input.

        La chiave sarà il tag del sottoelemento;
        Il valore sarà il contenuto del sottoelemento.
        """
        dictionary = {}
        for pair in zip(root, root.itertext()):
            element, text = pair
            dictionary[element.tag] = text
        return dictionary

    # Crea il dizionario da restitire in output
    json_results = {}

    # Per ogni elemento presente nel nodo results (XML):
    for result in results:

        # Ottieni gli indici
        result_indexes = get_indexes(result)
        contains_detection = False
        detect_filtered = {}

        # Controlla se esiste il campo detection e, se si,
        # aggiungilo all'output
        if "detection" in result_indexes:
            contains_detection = True
            detection = result[result_indexes["detection"]]
            detect_filtered = filter_detection(detection)

        # Ottieni dall'elemento i campi:
        # host, port, nvt, threat, severity, qod, descrizione
        host = result[result_indexes["host"]].text
        port = result[result_indexes["port"]].text
        nvt = result[result_indexes["nvt"]]
        threat = result[result_indexes["threat"]].text
        severity = result[result_indexes["severity"]].text
        qod = result[result_indexes["qod"]]
        description = result[result_indexes["description"]].text
        nvt_filtered = get_tag_and_text_in_xml_tag(nvt)
        qod_filtered = get_tag_and_text_in_xml_tag(qod)

        # Aggiungi al dizionario da restituire in output i campi ottenuti.
        if host not in json_results:
            json_results[host] = []
        json_element = {}
        json_element[column_names[0]] = port
        json_element[column_names[1]] = nvt_filtered
        json_element[column_names[2]] = threat
        json_element[column_names[3]] = severity
        if contains_detection:
            json_element[column_names[4]] = detect_filtered
        json_element[column_names[5]] = qod_filtered
        json_element[column_names[6]] = description
        json_results[host].append(json_element)

    return json_results


def create_results_count_json(results_count) -> dict:
    """
    Crea e restituisce un dizionario contenente le informazioni
    riguardanti il contenuto del nodo results_count (XML).
    I campi filtrati sono, per ogni count:
    - full
    - filtered
    """
    json_results_count = {"full": results_count[0].text,
                          "filtered": results_count[1].text}
    for count in results_count[2:]:
        full, filtered = count.itertext()
        json_results_count[count.tag] = {"full": full,
                                         "filtered": filtered}
    return json_results_count


def create_host_detailed_vulns_list(details, column_names) -> list:
    """
    Crea e restituisce un dizionario contenente le informazioni
    riguardanti il contenuto del nodo details (XML).
    I campi filtrati sono:
    - name (nome)
    - value (valore)
    - source (sorgente)
    - extra (dettagli aggiuntivi)
    """
    host_detailed_vulns = []

    # Per ogni elemento presente nel nodo details (XML):
    for detail in details[6:]:
        json_element = {}

        # Ottieni nome e valore dall'elemento e filtra quelli da scartare
        name, value = detail[0].text, detail[1].text
        if name == "EXIT_CODE" and value == "EXIT_NOTVULN":
            continue

        # Aggiungi al dizionario temporaneo i campi da filtrare
        json_element[column_names[0]] = name
        json_element[column_names[1]] = value
        source = detail[2]
        json_element[column_names[2]] = {}
        extra = detail[3]
        json_element[column_names[3]] = {}
        for elem in source:
            json_element[column_names[2]][elem.tag] = elem.text
        for elem in extra:
            json_element[column_names[2]][elem.tag] = elem.text

        # Inserisci al dizionario da restituire in output quello temporaneo
        host_detailed_vulns.append(json_element)

    return host_detailed_vulns


def create_errors_json(errors) -> dict:
    """
    Crea e restituisce un dizionario contenente le informazioni
    riguardanti il contenuto del nodo errors (XML).
    I campi filtrati sono:
    - port (porta)
    - description (descrizione)
    - nvt (Network Vulnerability Test)
    """
    json_errors = {}
    errors_count = errors[0].text

    # Inserisci nel dizionario da restituire in output il numero di errori
    json_errors["count"] = errors_count

    # Per ogni elemento presente nel nodo errors (XML):
    for error in errors[1:]:

        # Crea un dizionario basato su ogni host scansionato
        host = error[0].text
        if host not in json_errors:
            json_errors[host] = []

        # Filtra i campi relativi alla porta, alla descrizione e all'nvt
        # e inseriscili in un dizionario temporaneo
        port = error[1]
        description = error[2]
        json_element = {}
        json_element[port.tag] = port.text
        json_element[description.tag] = description.text
        nvt = {}
        for elem in error[3]:
            nvt[elem.tag] = elem.text
        json_element["nvt"] = nvt

        # Inserisci al dizionario da restituire in output quello temporaneo
        json_errors[host].append(json_element)

    return json_errors


def make_update_dict(to_add):
    """
    Filtra e restituisci, tra i parametri di input, quelli che
    devono essere aggiunti al file di output.
    """

    def get_owner():
        """
        Filtra e restituisci un dizionario contenente il sotto-nodo owner
        """
        # info(f"adding owner to the report.")
        owner = general_report[general_report_indexes["owner"]]
        return {owner.tag: owner[0].text}

    def get_hosts_number():
        """
        Filtra e restituisci un dizionario contenente il sotto-nodo hosts
        """
        # info(f"adding hosts number to the report.")
        hosts_number = report[report_indexes["hosts"]]
        return {hosts_number.tag: hosts_number[0].text}

    def get_vulns_number():
        """
        Filtra e restituisci un dizionario contenente il sotto-nodo vulns
        """
        # info(f"adding vulns number to the report.")
        vulns_number = report[report_indexes["vulns"]]
        return {vulns_number.tag: vulns_number[0].text}

    def get_os_number():
        """
        Filtra e restituisci un dizionario contenente il sotto-nodo os
        """
        # info(f"adding os number to the report.")
        os_number = report[report_indexes["os"]]
        return {os_number.tag: os_number[0].text}

    def get_apps_number():
        """
        Filtra e restituisci un dizionario contenente il sotto-nodo apps
        """
        # info(f"adding apps number to the report.")
        apps_number = report[report_indexes["apps"]]
        return {apps_number.tag: apps_number[0].text}

    def get_ssl_certs_number():
        """
        Filtra e restituisci un dizionario contenente i
        sotto-nodo ssl-certs
        """
        # info(f"adding ssl certs number to the report.")
        ssl_certs_number = report[report_indexes["ssl_certs"]]
        return {ssl_certs_number.tag: ssl_certs_number[0].text}

    def get_timestamp():
        """
        Filtra e restituisci un dizionario contenente i sotto-nodi:
        - timestamp
        - timezone
        - timezone-abbrev
        """
        # info(f"adding timestamp to the report.")
        timestamp = report[report_indexes["timestamp"]]
        timezone = report[report_indexes["timezone"]]
        timezone_abbrev = report[report_indexes["timezone_abbrev"]]
        date_format = r"%Y-%m-%dT%H:%M:%SZ"
        scan_timestamp = \
            f"{str(datetime.strptime(timestamp.text, date_format))} " \
            f"{timezone.text} ({timezone_abbrev.text})"
        return {timestamp.tag: scan_timestamp}

    def get_task():
        """
        Filtra e restituisci un dizionario contenente il sotto-nodo task
        """
        # info(f"adding task to the report.")
        task = report[report_indexes["task"]]
        return {task.tag: create_task_dict(task)}

    def get_ports():
        """
        Filtra e restituisci un dizionario contenente il sotto-nodo ports
        """
        # info(f"adding ports to the report.")
        ports = report[report_indexes["ports"]]
        port_column_names = ("host", "port", "severity", "threat")
        return {ports.tag:
                    create_ports_json(ports[1:], port_column_names)}

    def get_results():
        """
        Filtra e restituisci un dizionario contenente il sotto-nodo results
        """
        # info(f"adding results to the report.")
        results = report[report_indexes["results"]]
        result_column_names = ["port", "nvt", "threat", "severity",
                               "detection", "qod", "description"]
        return {results.tag: create_result_json(results, result_column_names)}

    def get_results_count():
        """
        Filtra e restituisci un dizionario contenente il sotto-nodo
        results-count
        """
        # info(f"adding results count to the report.")
        results_count = report[report_indexes["result_count"]]
        max_severity_full = report[report_indexes["severity"]][0].text
        max_severity_filtered = report[report_indexes["severity"]][1].text
        return {"results_count": create_results_count_json(results_count),
                "max_severity_full": max_severity_full,
                "max_severity_filtered": max_severity_filtered}

    def get_details():
        """
        Filtra e restituisci un dizionario contenente il sotto-nodo details
        """
        # info(f"adding details to the report.")
        try:
            details = report[report_indexes["host"]]
            detail_column_names = ["name", "value", "source", "extra"]
            return {"vuln_details": create_host_detailed_vulns_list(
                                        details, detail_column_names)}
        except:
            return {"vuln_details": []}

    def get_errors():
        """
        Filtra e restituisci un dizionario contenente il sotto-nodo errors
        """
        # info(f"adding errors to the report.")
        errors = report[report_indexes["errors"]]
        return {"errors": create_errors_json(errors)}

    to_return = {}

    if "all" in to_add:
        # info(f"adding everything to the report.")
        to_return.update(get_owner())
        to_return.update(get_hosts_number())
        to_return.update(get_vulns_number())
        to_return.update(get_os_number())
        to_return.update(get_apps_number())
        to_return.update(get_ssl_certs_number())
        to_return.update(get_timestamp())
        to_return.update(get_task())
        to_return.update(get_ports())
        to_return.update(get_results())
        to_return.update(get_results_count())
        to_return.update(get_details())
        to_return.update(get_errors())
        return to_return

    if "owner" in to_add: to_return.update(get_owner())
    if "hosts_number" in to_add: to_return.update(get_hosts_number())
    if "vulns_number" in to_add: to_return.update(get_vulns_number())
    if "os_number" in to_add: to_return.update(get_os_number())
    if "apps" in to_add: to_return.update(get_apps_number())
    if "ssl_certs" in to_add: to_return.update(get_ssl_certs_number())
    if "timestamp" in to_add: to_return.update(get_timestamp())
    if "tasks" in to_add: to_return.update(get_task())
    if "ports" in to_add: to_return.update(get_ports())
    if "results" in to_add: to_return.update(get_results())
    if "results_count" in to_add: to_return.update(get_results_count())
    if "details" in to_add: to_return.update(get_details())
    if "errors" in to_add: to_return.update(get_errors())

    return to_return


def create_report_json(args):
    """
    Crea e restituisce un dizionario contenente le informazioni riguardanti
    il contenuto dei nodi filtrati da make_update_dict.
    """
    json_report = {}
    to_add = []
    for k, v in args.items():
        if v:
            to_add.append(k)
    json_report.update(make_update_dict(to_add))
    return json_report


def write_report_to_file(report, output_file):
    """
    Scrive nel file di output output_file il report passato come parametro
    """
    print(f"Writing report to {output_file}.")
    with open(output_file, "w") as f:
        f.write(dumps(report, indent=4))


# Parser degli argomenti in input e relativi parametri inseriti
parser = get_parser()
args = vars(parser.parse_args())

# Acquisizione del parametro riguardante il file di input
input_file = args["input"]

# Lettura del file di input e acquisizione degli indici del nodo root (XML)
# info(f"Reading {input_file}.")
root = parse(input_file).getroot()
root_indexes = get_indexes(root)

# Acquisizione del nodo riguardante il report generico e relativi indici
general_report = root[root_indexes["report"]]
general_report_indexes = get_indexes(general_report)

# Acquisizione del nodo riguardante il report e relativi indici
report = general_report[general_report_indexes["report"]]
report_indexes = get_indexes(report)

# Creazione del report
# info("Creating json report.")
json_report = create_report_json(args)

# Computazione del nome del file di output
dir = dirname(input_file)
output_file = ("." if dir == '' else dir) + r"/" + \
              create_report_json({"tasks": True})["task"]["id"] + ".json"

# Scrittura all'interno del file di output
write_report_to_file(json_report, output_file)
