import json
import uuid

import stix2
from taxii2client import Collection


def loadJson(name):
    f = open('compact_output.json')
    pique = json.load(f)

    infrastructure = pique['additionalData']['projectName']

    quality_aspects = pique['factors']['quality_aspects']
    product_factors = pique['factors']['product_factors']
    measures = pique['measures']
    diagnostics = pique['diagnostics']

    out = open('pique2stix2.json', 'w')

    infrastructureObj = parseInfrastructure(infrastructure)
    diagObjects = parseDiagnostics(diagnostics)
    measureObjects = parseMeasures(measures)
    pfObjects = parseProductFactors(product_factors)

    infrastructureToDiagnostics = buildInfrastructureRelationship(diagObjects, infrastructureObj, "has")


    diagnosticsToMeasures = buildRelationship(diagObjects, measures, measureObjects, "derived-from")

    #not quite working....
    measuresToProductFactors = buildRelationship(measureObjects, product_factors, pfObjects, "derived-from")

    stixObjects = infrastructureObj + diagObjects + measureObjects + diagnosticsToMeasures + measuresToProductFactors

    buildBundle(out, stixObjects)
    out.close()


def buildInfrastructureRelationship(lower_stix, infrastructure, relationship_type):
    relationships = []
    for lower_stix_obj in lower_stix:
        relationships.append(buildRelationshipStix(infrastructure, lower_stix_obj, relationship_type))

    return relationships

def buildRelationship(lower_stix, upper_pique, upper_stix, relationship_type):
    relationships = []
    for upper in upper_pique:
        lower_stix_find = None
        upper_stix_find = None
        #find upper stix
        for upper_stix_obj in upper_stix:
            if upper_pique[upper]['name'] == upper_stix_obj.name:
                upper_stix_find = upper_stix_obj

        #find lower stix
        for weights in upper_pique[upper]['weights']:
            #each weight is the child node
            for lower in lower_stix:
                #print(type(lower_stix))
                if weights == lower.name:
                    lower_stix_find = lower

        if lower_stix_find is not None and upper_stix_find is not None:
            relationships.append(buildRelationshipStix(lower_stix_find, upper_stix_find, relationship_type))
    return relationships

def buildRelationshipStix(lower_stix, upper_stix, relationship_type):
    return stix2.v21.Relationship(
        type="relationship",
        relationship_type=relationship_type,
        source_ref=lower_stix.id,
        target_ref=upper_stix.id,
        id='relationship--' + str(uuid.uuid4()),
    )

def buildBundle(out, stixObjects):
    bundle = stix2.v21.Bundle(
        type='bundle',
        id='bundle--'+str(uuid.uuid4()),
        objects=stixObjects,
    )
    out.write(bundle.serialize(pretty=True))


def parseInfrastructure(infrastructure):
    #enter with one value
    infrastructureArray = []
    infrastructureObj = stix2.v21.Infrastructure(
        # uuid4 instructions from https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_q5ytzmajn6re
        id='infrastructure--'+str(uuid.uuid4()),
        name=infrastructure,
        description="Project under analysis"
    )
    infrastructureArray.append(infrastructureObj)
    return infrastructureArray


def parseProductFactors(product_factors):
    stixpackage = []
    for i in product_factors:
        if 'CWE' in product_factors[i]['name']:
            #calling everything a cwe vuln at this level
            stixpackage.append(buildStixVulnerability(product_factors[i]))

    return stixpackage

def parseMeasures(measures):
    stixpackage = []
    for i in measures:
        if 'CWE' in measures[i]['name'] or 'CVE' in measures[i]['name']:
            stixpackage.append(buildStixVulnerability(measures[i]))
        elif 'Yara' in measures[i]['name']:
            stixpackage.append(buildStixIndicator(measures[i]))
        else:
            print("nothing found for measure " + i)


    return stixpackage

def parseDiagnostics(diagnostics):
    stixpackage = []
    for i in diagnostics:
        if diagnostics[i]['toolName'] == 'cve-bin-tool' or diagnostics[i]['toolName'] == 'cwe_checker':
            stixpackage.append(buildStixVulnerability(diagnostics[i]))
        elif diagnostics[i]['toolName'] == 'yara-rules':
            stixpackage.append(buildStixIndicator(diagnostics[i]))
        else:
            print("nothing found for diagnostic " + i)

    return stixpackage


def buildStixVulnerability(diagnostic):
    #check to see if vulnerability exists already
    #fs = stix2.FileSystemSource('./cti-stix-common-objects/objects')
    #filter = stix2.Filter('type', '=', 'vulnerability')
    #vulnerabilities = fs.query([filter])
    vulnerability = stix2.v21.Vulnerability(
        # uuid4 instructions from https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_q5ytzmajn6re
        id='vulnerability--'+str(uuid.uuid4()),
        name=diagnostic['name'],
    )
    return vulnerability

def buildStixIndicator(diagnostic):
    indicator = stix2.v21.Indicator(
        name=diagnostic['name'],
        pattern="yara",
        pattern_type="yara",
    )
    return indicator

#not used until I can find a filesystem store of common stix objects.
def loadCommonObjects():
    # create FileSystemStore
    fs = stix2.FileSystemSource("cti-stix-common-objects/objects")

    # create TAXIICollectionSource -- Im guessing there is no standard repo for this.
    colxn = Collection('http://127.0.0.1:5000/trustgroup1/collections/91a7b528-80eb-42ed-a74d-c6fbd5a26116/',
                       user="user1", password="Password1")
    ts = stix2.TAXIICollectionSource(colxn)

    # add them both to the CompositeDataSource
    cs = stix2.CompositeDataSource()
    cs.add_data_sources([fs, ts])


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    #loadCommonObjects()
    loadJson('PyCharm')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
