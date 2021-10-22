import json
import uuid

import stix2


def loadJson(name):
    f = open('regular_output.json')
    pique = json.load(f)

    quality_aspects = pique['factors']['quality_aspects']
    product_factors = pique['factors']['product_factors']
    measures = pique['measures']
    diagnostics = pique['diagnostics']

    out = open('pique2stix2.json', 'w')


    diagObjects = parseDiagnostics(diagnostics)
    buildBundle(out, diagObjects)
    out.close()


def buildBundle(out, diagnosticObjects):
    bundle = stix2.v21.Bundle(
        type='bundle',
        id='bundle--'+str(uuid.uuid4()),
        objects=diagnosticObjects,
    )
    out.write(bundle.serialize(pretty=True))

def parseDiagnostics(diagnostics):
    stixpackage = []
    for i in diagnostics:
        if diagnostics[i]['toolName'] == 'cve-bin-tool' or diagnostics[i]['toolName'] == 'cwe_checker':
            stixpackage.append(buildStixVulnerability(diagnostics[i]))
        if diagnostics[i]['toolName'] == 'yara-rules':
            stixpackage.append(buildStixIndicator(diagnostics[i]))

    return stixpackage


def buildStixVulnerability(diagnostic):
    vulnerability = stix2.v21.Vulnerability(
        # uuid4 instructions from https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_q5ytzmajn6re
        id='vulnerability--'+str(uuid.uuid4()),
        name=diagnostic['name'],
    )
    return vulnerability
    #out.write(vulnerability.serialize(pretty=True))

def buildStixIndicator(diagnostic):
    indicator = stix2.v21.Indicator(
        name=diagnostic['name'],
        pattern="yara",
        pattern_type="yara",
    )
    return indicator
    #out.write(indicator.serialize(pretty=True))


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    loadJson('PyCharm')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
