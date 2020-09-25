"""
Questo modulo si occupa di estrarre, dal file generato
dal modulo xml-parser.py, i campi relativi alle
CVE (Common Vulnerabilities and Exposures).
"""
from json import load
from argparse import ArgumentParser
from os.path import dirname, splitext


def get_parser():
    """
    Crea e restituisce il parser dei parametri
    inseriti a linea di comando.
    """
    parser = ArgumentParser(
        description='Filter CVEs out of a JSON-parsed'
                    'XML report created by OpenVAS.')
    parser.add_argument('--input', required=True, help='Input file')

    return parser


def get_input_file(parser):
    """
    Filtra, tra gli argomenti inseriti in input, il file da processare
    """
    return vars(parser.parse_args())["input"]


def get_file_data(input_file):
    """
    Legge il file json in input e ne restituisce
    il dizionario corrispondente
    """
    with open(input_file) as json_file:
        return load(json_file)


def get_cve(results):
    """
        Filtra, dal sotto-nodo results (XML) del report,
        il campo CVE.

        Restituisce poi una lista dei campi filtrati.
    """
    already_seen = set()
    cves = list()

    for host in [k for k, _ in results.items()]:

        # Per ogni host presente nel nodo results (XML):
        for d in results[host]:

            # Estrai il dizionario relativo alle CVE
            cve = d['nvt']['cve']

            # E se non è vuoto
            if cve != "NOCVE":

                # Separa tutte le CVE in una lista
                for x in cve.split(','):

                    # E se non l'abbiamo già incontrata prima
                    if x not in already_seen:
                        # Aggiungila alla lista delle CVE da restituire
                        already_seen.add(x)
                        cves.append(x.replace(' ', ''))

    return cves


def get_output_file_name(input_file):
    """
    Computa e restituisce il nome del file di output
    """
    drnm = dirname(input_file)
    return ("." if drnm == '' else drnm) + r"/" \
           + splitext(input_file)[0] + ".cve"


def write_list_to_file(output_file, lst):
    """
    Scrive nel file di output output_file la 
    lista passata come parametro
    """
    with open(output_file, "w") as out:
        for s in lst:
            out.write(s + '\n')


def main():
    """
    Main function. (Oh, really?)
    """
    input_file = get_input_file(get_parser())
    data = get_file_data(input_file)
    cves = get_cve(data["results"])
    write_list_to_file(get_output_file_name(input_file), cves)


if __name__ == '__main__':
    main()
