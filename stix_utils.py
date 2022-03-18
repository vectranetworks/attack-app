from pprint import pprint
import requests
import json
from stix2 import MemoryStore
from stix2 import Filter
from stix2.utils import get_type_from_id
from itertools import chain


def get_data_from_branch(domain, file_name=None):
    """get the ATT&CK STIX data from MITRE/CTI. Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'. Branch should typically be master."""
    stix_json = requests.get(f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}.json").json()
    if file_name:
        # logging.info(f'Writing attack data to file')
        with open(file_name, 'w') as outfile:
            json.dump(stix_json, outfile)
    return MemoryStore(stix_data=stix_json["objects"])


def get_group_by_alias(thesrc, alias):
    return thesrc.query([
        Filter('type', '=', 'intrusion-set'),
        Filter('aliases', '=', alias)
    ])


def get_groups(thesrc):
    return thesrc.query([ Filter("type", "=", "intrusion-set") ])


def get_software(thesrc):
    return list(chain.from_iterable(
        thesrc.query(f) for f in [
            Filter("type", "=", "tool"),
            Filter("type", "=", "malware")
        ]
    ))


def get_malware_by_alias(thesrc, alias):
    return thesrc.query([
        Filter('type', '=', 'malware'),
        Filter('x_mitre_aliases', '=', alias)
    ])


def get_malware_by_alias(thesrc, alias):
    return thesrc.query([
        Filter('type', '=', 'malware'),
        # Filter('type', '=', 'tool'),
        Filter('x_mitre_aliases', '=', alias)
    ])


def get_tool_by_alias(thesrc, alias):
    return thesrc.query([
        # Filter('type', '=', 'malware'),
        Filter('type', '=', 'tool'),
        Filter('x_mitre_aliases', '=', alias)
    ])


def mitre_attack_from_attack_pattern(apl):
    eidl = []
    for ap in apl:
        eidl.append(ap.get('external_references')[0].get('external_id'))
    return eidl


# src = get_data_from_branch("enterprise-attack")
# apt29 = get_group_by_alias(src, 'APT29')
# apl = get_techniques_by_group_software(src, apt29.get('id'))
# mitre_attack_from_attack_pattern(apl)


# See section below on "Removing revoked and deprecated objects"
def remove_revoked_deprecated(stix_objects):
    """Remove any revoked or deprecated objects from queries made to the data source"""
    # Note we use .get() because the property may not be present in the JSON data. The default is False
    # if the property is not set.
    return list(
        filter(
            lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
            stix_objects
        )
    )


def get_related(thesrc, src_type, rel_type, target_type, reverse=False):
    """
    build relationship mappings
       params:
         thesrc: MemoryStore to build relationship lookups for
         src_type: source type for the relationships, e.g "attack-pattern"
         rel_type: relationship type for the relationships, e.g "uses"
         target_type: target type for the relationship, e.g "intrusion-set"
         reverse: build reverse mapping of target to source
    """
    relationships = thesrc.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', rel_type),
        Filter('revoked', '=', False),
    ])
    # See section below on "Removing revoked and deprecated objects"
    relationships = remove_revoked_deprecated(relationships)
    # stix_id => [ { relationship, related_object_id } for each related object ]
    id_to_related = {}
    # build the dict
    for relationship in relationships:
        if src_type in relationship.source_ref and target_type in relationship.target_ref:
            if (relationship.source_ref in id_to_related and not reverse) or (relationship.target_ref in id_to_related and reverse):
                # append to existing entry
                if not reverse:
                    id_to_related[relationship.source_ref].append({
                        "relationship": relationship,
                        "id": relationship.target_ref
                    })
                else:
                    id_to_related[relationship.target_ref].append({
                        "relationship": relationship,
                        "id": relationship.source_ref
                    })
            else:
                # create a new entry
                if not reverse:
                    id_to_related[relationship.source_ref] = [{
                        "relationship": relationship,
                        "id": relationship.target_ref
                    }]
                else:
                    id_to_related[relationship.target_ref] = [{
                        "relationship": relationship,
                        "id": relationship.source_ref
                    }]
    # all objects of relevant type
    if not reverse:
        targets = thesrc.query([
            Filter('type', '=', target_type),
            Filter('revoked', '=', False)
        ])
    else:
        targets = thesrc.query([
            Filter('type', '=', src_type),
            Filter('revoked', '=', False)
        ])
    # build lookup of stixID to stix object
    id_to_target = {}
    for target in targets:
        id_to_target[target.id] = target
    # build final output mappings
    output = {}
    for stix_id in id_to_related:
        value = []
        for related in id_to_related[stix_id]:
            if not related["id"] in id_to_target:
                continue  # targeting a revoked object
            value.append({
                "object": id_to_target[related["id"]],
                "relationship": related["relationship"]
            })
        output[stix_id] = value
    return output


def getTacticsByMatrix(thesrc):
    tactics = {}
    matrix = thesrc.query([
        Filter('type', '=', 'x-mitre-matrix'),
    ])

    for i in range(len(matrix)):
        tactics[matrix[i]['name']] = []
        for tactic_id in matrix[i]['tactic_refs']:
            tactics[matrix[i]['name']].append(thesrc.get(tactic_id))

    return tactics


# software:group
def software_used_by_groups(thesrc):
    """returns group_id => {software, relationship} for each software used by the group."""
    tools_used_by_group = get_related(thesrc, "intrusion-set", "uses", "tool")
    malware_used_by_group = get_related(thesrc, "intrusion-set", "uses", "malware")
    return {**tools_used_by_group, **malware_used_by_group}


def groups_using_software(thesrc):
    """returns software_id => {group, relationship} for each group using the software."""
    groups_using_tool = get_related(thesrc, "intrusion-set", "uses", "tool", reverse=True)
    groups_using_malware = get_related(thesrc, "intrusion-set", "uses", "malware", reverse=True)
    return {**groups_using_tool, **groups_using_malware}


# technique:group
def techniques_used_by_groups(thesrc):
    """returns group_id => {technique, relationship} for each technique used by the group."""
    return get_related(thesrc, "intrusion-set", "uses", "attack-pattern")


def groups_using_technique(thesrc):
    """returns technique_id => {group, relationship} for each group using the technique."""
    return get_related(thesrc, "intrusion-set", "uses", "attack-pattern", reverse=True)


# technique:software
def techniques_used_by_software(thesrc):
    """return software_id => {technique, relationship} for each technique used by the software."""
    techniques_by_tool = get_related(thesrc, "tool", "uses", "attack-pattern")
    techniques_by_malware = get_related(thesrc, "malware", "uses", "attack-pattern")
    return {**techniques_by_tool, **techniques_by_malware}


def software_using_technique(thesrc):
    """return technique_id  => {software, relationship} for each software using the technique."""
    tools_by_technique_id = get_related(thesrc, "tool", "uses", "attack-pattern", reverse=True)
    malware_by_technique_id = get_related(thesrc, "malware", "uses", "attack-pattern", reverse=True)
    return {**tools_by_technique_id, **malware_by_technique_id}


# technique:mitigation
def mitigation_mitigates_techniques(thesrc):
    """return mitigation_id => {technique, relationship} for each technique mitigated by the mitigation."""
    return get_related(thesrc, "course-of-action", "mitigates", "attack-pattern", reverse=False)


def technique_mitigated_by_mitigations(thesrc):
    """return technique_id => {mitigation, relationship} for each mitigation of the technique."""
    return get_related(thesrc, "course-of-action", "mitigates", "attack-pattern", reverse=True)


# technique:sub-technique
def subtechniques_of(thesrc):
    """return technique_id => {subtechnique, relationship} for each subtechnique of the technique."""
    return get_related(thesrc, "attack-pattern", "subtechnique-of", "attack-pattern", reverse=True)


def parent_technique_of(thesrc):
    """return subtechnique_id => {technique, relationship} describing the parent technique of the subtechnique"""
    return get_related(thesrc, "attack-pattern", "subtechnique-of", "attack-pattern")[0]


# technique:data-component
def datacomponent_detects_techniques(thesrc):
    """return datacomponent_id => {technique, relationship} describing the detections of each data component"""
    return get_related(thesrc, "x-mitre-data-component", "detects", "attack-pattern")


def technique_detected_by_datacomponents(thesrc):
    """return technique_id => {datacomponent, relationship} describing the data components that can detect the technique"""
    return get_related(thesrc, "x-mitre-data-component", "detects", "attack-pattern", reverse=True)


def get_techniques_by_group_software(thesrc, group_stix_id):
    # get the malware, tools that the group uses
    group_uses = [
        r for r in thesrc.relationships(group_stix_id, 'uses', source_only=True)
        if get_type_from_id(r.target_ref) in ['malware', 'tool']
    ]
    # get the technique stix ids that the malware, tools use
    software_uses = thesrc.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', 'uses'),
        Filter('source_ref', 'in', [r.source_ref for r in group_uses])
    ])
    # get the techniques themselves
    return thesrc.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('id', 'in', [r.target_ref for r in software_uses])
    ])


def mitre_attack_from_technique_attack_pattern(apl):
    eidl = []
    for ap in apl:
        eidl.append(ap.get('external_references')[0].get('external_id'))
    return eidl


def mitre_attack_from_software_attack_pattern(apl):
    eidl = []
    for ap in apl:
        eidl.append(ap['object'].get('external_references')[0].get('external_id'))
    return eidl
