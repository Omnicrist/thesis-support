"""
Questo modulo si occupa di eseguire richieste all'API del CIRCL per
ogni CVE contenuta nel file di input generato da cve_extractor.py
"""
import time
from argparse import ArgumentParser
import concurrent.futures
import requests
from multiprocessing import cpu_count
import json
from os.path import dirname, splitext


def get_parser():
    """
    Crea e restituisce il parser dei parametri inseriti a linea di comando.
    """
    parser = ArgumentParser(
        description='Filter CVEs out of a JSON-parsed'
                    'XML report created by OpenVAS.')
    parser.add_argument('--input', required=True,
                        help='Input file')

    return parser


def get_input_file(parser):
    """
    Filtra, tra gli argomenti inseriti in input, il file da processare
    """
    return vars(parser.parse_args())["input"]


def get_file_data(input_file):
    """
    Legge il file di input e ne restituisce
    una lista di CVEcorrispondenti, senza il
    Line Feed ('\\n') oppure, su Windows, ('\\r\\n')
    """
    lst = list()
    with open(input_file) as f:
        for line in f.readlines():
            lst.append(line.replace('\n', ''))
    return lst


def get_output_file_name(input_file, api_provider):
    """
    Computa e restituisce il nome del file di output
    """
    drnm = dirname(input_file)
    return ("." if drnm == '' else drnm) + r"/" + \
           splitext(input_file)[0] + "_" + api_provider + ".cve"


def process_cve(url, cve):
    """
    Esegui la richiesta all'API del CIRCL (url) riguardo la CVE
    passata come parametro

    Restituisce il dizionario corrispondente al json restituito
    in caso di successo, None altrimenti
    """
    try:
        # time.sleep(0.25)
        return json.loads(requests.get(url + cve).text)
    except:
        return None


def generator(data):
    """
    Generatore che restituisce la coppia (indice, cve) per ogni CVE
    presente nella lista inserita in input.
    """
    for index, cve in enumerate(data, start=1):
        yield index, cve


def main():
    """
    Main function (Damn I'm really smart.)
    """
    # Acquisizione del parametro riguardante il file di input e
    # il relativo contenuto
    input_file = get_input_file(get_parser())
    data = get_file_data(input_file)

    # API del CIRCL per la richiesta riguardante le CVE
    url = r"https://cve.circl.lu/api/cve/"

    # Dizionario che conterrà le informazioni relative alle CVE
    out = {}

    # Parametri per una pretty-print del CVE-processing
    length = len(data)
    pad = len(str(length))

    # Parametri per la gestione della componente parallela del programma
    max_threads = cpu_count()
    threads = {}
    threads_num = 0

    # Crea una ThreadPoolExecutor
    with concurrent.futures.ThreadPoolExecutor() as executor:

        # Per ogni indice e CVE contenuta nel file di input
        for index, cve in generator(data):
            try:
                # Se abbiamo raggiunto il massimo di thread
                # eseguibili in parallelo
                if threads_num == max_threads:

                    # Per ognuno di essi filtra attendi il completamento
                    # ed ottieni il risultato della computazione
                    for t_cve, thread in threads.items():
                        r = thread.result()
                        # Effettua controlli sul risultato ed aggiungilo
                        # al dizionario contenente le informazioni
                        if r is not None:
                            out[t_cve] = r
                        else:
                            print(f"Not found: {url + t_cve}")

                    # Pulisci la lista contenente i thread
                    # e resetta il contatore
                    threads.clear()
                    threads_num = 0

                # Comunica a schermo le CVE che è attualmente processata
                print(f"Processing: {cve:<14} ({index:<{pad}}/{length})")

                # Crea un thread per processare la CVE e
                # aggiungilo alla lista dei threads già
                # esistenti, incrementando il contatore.
                threads[cve] = executor.submit(process_cve, url, cve)
                threads_num += 1
            except:
                # Se ci sono errori, comunicali e salta il
                # processing dell'attuale CVE
                print(f"Generic error processing: {url + cve}")
                continue

    # Apri il file di output e scrivi il dizionario contenente
    # le informazioni relative alle CVE processate
    with open(get_output_file_name(input_file, "circl"), "w") as f:
        f.write(json.dumps(out, indent=4))


if __name__ == '__main__':
    main()
