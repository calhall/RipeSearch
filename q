import sys
import requests
import argparse
import json
from netaddr import iprange_to_cidrs

# To use this script pass a file as an argument containing your target's known domains
# These domains should be line seperated

PERSON_RIPE_URL = "https://apps.db.ripe.net/db-web-ui/api/rest/fulltextsearch/select?facet=true&format=xml&hl=true&q=({query})+AND+(object-type:inetnum+OR+object-type:mntner+OR+object-type:person+OR+object-type:role+OR+object-type:organisation)&wt=json&rows=100&start={start}"
INETNUM_RIPE_URL = "https://apps.db.ripe.net/db-web-ui/api/rest/fulltextsearch/select?facet=true&format=xml&hl=true&q=({query})+AND+(object-type:inetnum)&wt=json&rows=100&start={start}"


def fulltext_query(query, url):
    """run a query, fetch all result pages and return them"""
    all_data = []
    start = 0
    while True:
        response = requests.get(
            url.format(query=query, start=start), headers={"Accept": "application/json"}
        )
        data = response.json()
        # rangeCount = int(data['lsts'][len(data['lsts'])-2]['lst']['lsts'][0]['lst']['lsts'][0]['lst']['ints'][0]['int']['value'])
        # print (data['result']['start'])
        # if (rangeCount < start+100:
        #    break
        # else:
        all_data.append(data)
        break
        # start += 100

    return all_data


def extract_person_data(all_data, term):
    """extract relevant information from all the data returned by the RIPE search"""
    people = []
    for data in all_data:
        for doc in data["result"]["docs"]:
            inetnum = ""
            reason = ""
            try:
                for _str in doc["doc"]["strs"]:
                    if _str["str"]["name"] == "lookup-key":
                        person = _str["str"]["value"]
                        people.append(person)
            except:
                pass
    return people


def extract_data(all_data, term):
    """extract relevant information from all the data returned by the RIPE search"""
    cidrs = []
    termsplit = term.split(" ")
    for data in all_data:
        try:
            for doc in data["result"]["docs"]:
                inetnum = ""
                reason = ""
                try:
                    for _str in doc["doc"]["strs"]:
                        if _str["str"]["name"] == "lookup-key":
                            inetnum = _str["str"]["value"]
                        elif _str["str"]["name"] == "netname":
                            if (
                                termsplit[0].upper() in _str["str"]["value"].upper()
                                and reason == ""
                            ):
                                reason = (
                                    " - Registered to "
                                    + _str["str"]["value"]
                                    + " on RIPE"
                                )
                        elif _str["str"]["name"] == "descr":
                            if (
                                termsplit[0].upper() in _str["str"]["value"].upper()
                                and reason == ""
                            ):
                                reason = (
                                    " - Registration description contains "
                                    + _str["str"]["value"]
                                )
                except Exception as e:
                    pass
                start, end = inetnum.split(" - ")
                for entry in iprange_to_cidrs(start, end):
                    for cidr in cidrs:
                        if cidr == entry:
                            break
                    else:
                        cidrobject = str(entry)
                        cidrs.append(cidrobject)
        except:
            pass
    return cidrs


def main():

    print("""\


| . \| || . \| __> / __>| __>| . || . \|  _>| | |
|   /| ||  _/| _>  \__ \| _> |   ||   /| <__|   |
|_\_\|_||_|  |___> <___/|___>|_|_||_\_\`___/|_|_|


                    """)

    parser = argparse.ArgumentParser(description="Identify IP Ranges on RIPE")
    parser.add_argument(
        "-d",
        "--domains",
        help="Pass a file containing a list of domains to search for eg. Email addresses",
    )
    parser.add_argument(
        "-s",
        "--strings",
        help="Pass a file containing a list of strings to search for eg. Organisation names",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print more information on the origins of identified IP ranges",
    )
    args = parser.parse_args()
    if args.domains:
        for domain in open(args.domains):
            all_data = fulltext_query(domain.strip(), PERSON_RIPE_URL)
            try:
                people = extract_person_data(all_data, domain.strip())
            except:
                people = []
            for person in people:
                all_data = fulltext_query(person, INETNUM_RIPE_URL)
                cidrs = extract_data(all_data, domain.strip())

                for cidr in cidrs:
                    if args.verbose:
                        print(
                            cidr.replace(",", "")
                            + " was registered with a "
                            + domain.strip()
                            + " email address"
                        )
                    else:
                        print(cidr.replace(",", ""))

    elif args.strings:
        for string in open(args.strings):
            all_data = fulltext_query(string.strip(), INETNUM_RIPE_URL)
            cidrs = extract_data(all_data, string.strip())

            for cidr in cidrs:
                if args.verbose:
                    print(
                        cidr.replace(",", "")
                        + " contains '"
                        + string.strip()
                        + "' within the WHOIS record"
                    )
                else:
                    print(cidr.replace(",", ""))

    else:
        print(
            """\
This script is designed to identify target IP ranges stored by RIPE NCC.

Ranges can identified using the following to search types:

String search [-s]: Searching for IP ranges registered to target registrants (e.g. 'Example Corp')
Domain search [-d]: Searching for IP ranges registered by individuals using a target email (e.g. 'admin@example.org')

"""
        )


if __name__ == "__main__":
    main()
