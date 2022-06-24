import logging
import os
import sys
import json
import re
from datetime import datetime, timedelta
import stix2

try:
    from stix2 import Filter
    from stix2 import MemoryStore
    from stix_utils import get_data_from_branch, get_group_by_alias, get_techniques_by_group_software, \
        get_malware_by_alias, get_tool_by_alias, techniques_used_by_software, mitre_attack_from_software_attack_pattern, \
        get_software, get_groups, groups_using_technique, software_using_technique

    from flask import Flask, render_template, request, redirect, url_for, json, jsonify, send_from_directory
except Exception as error:
    print(f'\nMissing import requirements: {str(error)}\n')

LOG = logging.getLogger(__name__)
ATTACK_DATA = 'enterprise-attack.json'
VECTRA_TNUM = 'Vectra_Detections_to_Mitre_Technique_Map.json'
VECTRA_TNUM_V10 = 'Vectra_platform_coverage_for_ATT&CK_v10.json'
VECTRA_TNUM_V11 = 'Vectra_platform_coverage_for_ATT&CK_v11.json'

TNUMBER_DETECTION_MAP = {}
MITRE_DESCRIPTIONS = 'mitre_descriptions3.json'
SRC = stix2.MemoryStore


def set_logging(level):
    log_level = logging.DEBUG if level == 'DEBUG' else logging.INFO
    logging.basicConfig(level=log_level)
    # logging.basicConfig(filename='/var/log/mitre_storyboard.log', format='%(asctime)s: %(message)s', level=logging.INFO)


set_logging('INFO')

app = Flask(__name__, static_url_path='', static_folder='mitre')


def load_mitre_data(file_name, days=7):
    """
    Loads and returns attack data from file that has been updated less than days.  Otherwise, loads attack from web.

    :param file_name: ATT&CK data file name
    :param days: number of days to compare file modification time against.  Default=7
    :return: STIX MemoryStore object with ATT&CK data
    """

    if os.path.exists(file_name):
        last_modified = datetime.fromtimestamp(os.path.getmtime(file_name))
        needs_update = last_modified < (datetime.now() - timedelta(days=days))
        if needs_update:
            logging.info(f'File {file_name} update needed:{needs_update}.  Retrieving attack data from web and saving.')
            mitre_src = get_data_from_branch("enterprise-attack", file_name)
            # mitre_src.save_to_file(file_name) appears to be broken.  Manually collect and write file.
        else:
            logging.info(f'File: {file_name} update needed:{needs_update}.  Loading attack data from file.')
            mitre_src = MemoryStore()
            mitre_src.load_from_file(file_name)

        return mitre_src
    else:
        logging.info(f'OS Path does not exist: {file_name}.  Retrieving attack data from web and saving.  '
                     f'This may take a minute.')
        mitre_src = get_data_from_branch("enterprise-attack", ATTACK_DATA)
        #  mitre_src.save_to_file(file_name)  routine is broken, manual saving in preceding call
        return mitre_src


def load_detection_technique_json(infile):
    with open(infile, 'r') as fh:
        mapping = json.load(fh)
    return mapping


def map_technique_detection2(map_dict, t_number, product='all', category='all'):
    """
    Generates a list of Detection objects based on product and category that map to a T-number.

    :param map_dict: dictionary mapping T-numbers to Vectra Detections
    :t_number: MITRE T-number to map detections to
    :param product: 'Detect for Network', 'Detect for O365', etc.
    :param category: Vectra Detection category proper name
    :return: List of Detection Class object(s).
    """
    # det_t_dict = dict()
    results_list = list()

    def map_det_tnum(vtd, tn):
        det_t_dict = dict()
        for det, t in vtd.items():
            for s in filter(lambda x: tn in x, t): det_t_dict[det] = s
        return det_t_dict
    if product == 'all' and category == 'all':
        for prod in map_dict.keys():
            for cat in map_dict[prod].keys():
                results_dict = map_det_tnum(map_dict.get(prod).get(cat), t_number)
                for d in results_dict.keys():
                    results_list.append(Detection(d, cat, prod, results_dict[d])) if len(d) > 0 \
                        else results_list.append(None)
    return results_list


def compile_techniques2(map_dict, t_number_list):
    """
    Compiles a list of Detection objects that contain techniques based on supplied list of T-numbers

    :param map_dict: dictionary mapping T-numbers to Vectra Detections
    :param t_number_list: ['T123', 'T345']
    :return: list of Detection class objects
    """
    t_list = list()
    for t in t_number_list:
        res_list = map_technique_detection2(map_dict, t)
        if len(res_list) > 0:
            t_list += res_list
        else:
            t_list.append(Detection('No detection found', None, None, t))
    return t_list


def extract_tnum(ap):
    for i in ap.get('external_references'):
        if i.get('source_name') == 'mitre-attack':
            return i.get('external_id').split('.')[0]
    return None


def map_detection_technique(map_dict, t_number, product='all', category='all'):
    """
    Maps Detections to supplied T-number.
    :param map_dict: Vectra supplied detection and T-number mapping file
    :param t_number: Proper MITRE ATT&CK Tnumber
    :param product:
    :param category:
    :return: List of Vectra detections
    """
    det_list = list()
    LOG.info('Processing tnum: {}'.format(t_number))

    def map_det_tnum(vtd, tn):
        for det, t in vtd.items():
            for s in filter(lambda x: tn in x, t):
                if type(s) is list:
                    continue
                else:
                    det_list.append(det)
    if product == 'all' and category == 'all':
        for prod in map_dict.keys():
            for cat in map_dict[prod].keys():
                map_det_tnum(map_dict.get(prod).get(cat), t_number)
    return det_list


def map_detection_technique2(map_dict, t_number):
    """
    Maps Detections to supplied T-number.  Use with MITRE v10+ JSON
    :param map_dict: Vectra supplied detection and T-number mapping file
    :param t_number: Proper MITRE ATT&CK T-number
    :return: List of Vectra detections
    """
    pattern = r'^(.*)'
    techniques = map_dict.get('techniques')
    for t in techniques:
        if t.get('techniqueID', '') == t_number:
            comment = t.get('comment', '')
            if len(comment):
                dlist = re.split(pattern, comment, flags=re.MULTILINE)
                if 'Example Alerts:' in dlist:
                    d = dlist[dlist.index('Example Alerts:') + 1:-1]
                    # remove \n
                    return [i for i in d if '\n' not in i]
                elif 'Relevant Detections:' in dlist:
                    d = dlist[dlist.index('Relevant Detections:') + 1:-1]
                    # remove \n
                    return [i for i in d if '\n' not in i]
            else:
                logging.info('No comment found for T-number {}'.format(t_number))
                return []
    logging.info('T-number {} not found in mapping file'.format(t_number))
    return []


def load_tnum_descriptions(t_descr_file):
    with open(t_descr_file, 'r') as infile:
        return json.load(infile)


def get_tnum_description(t_num, t_descr_dict):
    return t_descr_dict.get(t_num, '')


def map_detections_mitre_techniques(apl, map_dict, t_det_descriptions):
    """
    Maps Vectra Detections to MITRE T-numbers and associated descriptions.  Returns a dict containing the information

    :param apl: list of attack patterns
    :param map_dict: Vectra Detection to T-number mapping
    :param t_det_descriptions: Vectra's T-number descriptions mapping
    :return: dictionary in the following format:
    {
    'Initial Access': [
        {'T1': {'dets': ["External Remote Access"], 'descr': 'some desc'}},
        {'T2': {'dets': ["Hidden HTTP Tunnel", "Hidden HTTPS Tunnel"], 'descr': 'some desc'}}
        ],
    'Discovery': [
        {'T11': {'dets': ["det1", "det2"], 'descr': 'some desc'}},
        {'T22': {'dets': ["det1", "det2"], 'descr': 'some desc'}}
        ]
    }
    """

    tnum_description_dict = load_tnum_descriptions(MITRE_DESCRIPTIONS)
    tnum_detection_map = dict()

    # Determine if apl is list of [{object: AttackPattern, relationship: Relationship}] which indicates from software
    if 'object' in apl[0].keys():
        new_apl = [x.get('object') for x in apl]
        apl = new_apl
        del new_apl

    for attack_pattern in apl:
        t_dict = dict()
        t_num = extract_tnum(attack_pattern)
        det_list = list(set(map_detection_technique2(map_dict, t_num)))
        tnum_descr = get_tnum_description(t_num, tnum_description_dict)

        # Loop through mitre phases
        if attack_pattern.get('kill_chain_phases'):
            for phase_obj in attack_pattern.get('kill_chain_phases'):
                if phase_obj.get('kill_chain_name') == 'mitre-attack':
                    phase = phase_obj.get('phase_name')
                    LOG.debug('Phase: {}'.format(phase))
                    ## t_dict = {t_num: {'detections': det_list, 'description': tnum_descr}}
                    t_dict[t_num] = {'detections': det_list, 'description': tnum_descr}
                    '''
                    When adding a new dict key, check to see if in existing key list, and if not 
                    md = {**md, **{new dict}}
                    Check to see if list item exists, only add if does not exist
                    '''

                    if phase not in tnum_detection_map.keys():
                        # Phase does not exist in dictionary, add
                        # tnum_detection_map = {**tnum_detection_map, **{phase: t_dict}} //not correct way, no list
                        ## tnum_detection_map[phase] = [t_dict]
                        tnum_detection_map[phase] = t_dict
                        LOG.debug('Phase not in dict detection map, added. New dict: {}'.format(tnum_detection_map))
                    else:
                        # Phase exists in dictionary; Build list of keys (T-numbers) from phase
                        LOG.debug('Phase {} in dict detection map.'.format(phase))
                        k_l = list()
                        p = tnum_detection_map.get(phase)
                        ## for i in p:
                        ##     k_l += i.keys()
                        # Check if t_num is in phase already, otherwise add
                        ## if t_num not in k_l:
                        if t_num not in tnum_detection_map.get(phase).keys():
                            # T-number is not in list of keys, add to dictionary
                            ## tnum_detection_map[phase].append(t_dict)
                            tnum_detection_map[phase][t_num] = t_dict[t_num]
                            LOG.debug('t_num not in detection map, added.  New dict: {}'.format(tnum_detection_map))
                        else:
                            continue
                else:
                    # Phase not from mitre-attack
                    LOG.error('Phase not from mitre-attack for T-number: {}'.format(t_num))
        else:
            # No phase from attack pattern
            LOG.error('No "kill_chain_phases" present for T-number: {}'.format(t_num))

    return tnum_detection_map


def get_techniques_by_software(soft_tech, m_id):
    return soft_tech.get(m_id)


@app.before_first_request
def first_load_mitre_data():
    global SRC, TNUMBER_DETECTION_MAP
    app.logger.info("Loading MITRE ATT&CK Data...")
    SRC = load_mitre_data(ATTACK_DATA)
    TNUMBER_DETECTION_MAP = load_detection_technique_json(VECTRA_TNUM_V11)


@app.route('/')
def in_main():
    app.logger.info("main route")
    return send_from_directory('mitre', 'index.html')


@app.route('/api/groups')
def get_group_list():
    groups = get_groups(SRC)
    '''return jsonify([{'name': g.get('name'), 'aliases': g.get('aliases')} for g in groups])'''

    groups_list = [{'name': g.get('name'), 'aliases': g.get('aliases')} for g in groups]
    response = app.response_class(
        response=json.dumps(groups_list),
        status=200,
        mimetype='application/json'
    )
    return response


@app.route('/api/get_group_info')
def get_group_info(group=None):
    group = request.args.get('group')
    group_intrusion_set = get_group_by_alias(SRC, group)
    if len(group_intrusion_set) < 1:
        LOG.info('Group with name or alias [ {} ] not found.'.format(group))
        response = app.response_class(
            response=json.dumps({'error': 'group {} not found'.format(group)}),
            status=200,
            mimetype='application/json'
        )
        return response
    else:
        response = app.response_class(
            response=json.dumps({"group": group, "description": group_intrusion_set[0].get('description', '')}),
            status=200,
            mimetype='application/json'
        )
        return response


@app.route('/api/get_group')
def get_group(group=None):
    group = request.args.get('group')
    group_intrusion_set = get_group_by_alias(SRC, group)
    if len(group_intrusion_set) < 1:
        LOG.info('Group with name or alias [ {} ] not found.'.format(group))
        response = app.response_class(
            response=json.dumps({'error': 'group {} not found'.format(group)}),
            status=200,
            mimetype='application/json'
        )
        return response
    elif len(group_intrusion_set) > 1:
        LOG.info('{} groups found with name or alias'.format(len(group_intrusion_set)))

    group_apl = get_techniques_by_group_software(SRC, group_intrusion_set[0].get('id'))
    # map_dict = load_detection_technique_json(VECTRA_TNUM)
    det_descriptions = load_tnum_descriptions(MITRE_DESCRIPTIONS)
    group_to_t_vectra_map = map_detections_mitre_techniques(group_apl, TNUMBER_DETECTION_MAP, det_descriptions)
    # Add Group name, description
    group_to_t_vectra_map['name'] = group
    group_to_t_vectra_map['description'] = group_intrusion_set[0].get('description', '')

    response = app.response_class(
        response=json.dumps(group_to_t_vectra_map),
        status=200,
        mimetype='application/json'
    )
    return response


@app.route('/api/software')
def get_software_list():
    software = get_software(SRC)
    '''return jsonify([{'name': s.get('name'), 'aliases': s.get('x_mitre_aliases')} for s in software])'''

    software_list = [{'name': s.get('name'), 'aliases': s.get('x_mitre_aliases')} for s in software]
    response = app.response_class(
        response=json.dumps(software_list),
        status=200,
        mimetype='application/json'
    )
    return response


@app.route('/api/get_malware_tool')
def get_malware_tool(software=None):
    software_name = request.args.get('software')
    LOG.info('software_name:{}'.format(software_name))
    malware = get_malware_by_alias(SRC, software_name) or get_tool_by_alias(SRC, software_name)
    if len(malware) < 1:
        print('Malware with name or alias [ {} ] not found.  \nRefer to MITRE ATT&CK.'.format(software_name))
        sys.exit(0)
    elif len(malware) > 1:
        print('{} malware found with name or alias'.format(len(malware)))

    malware_apl = get_techniques_by_software(techniques_used_by_software(SRC), malware[0].get('id'))
    # map_dict = load_detection_technique_json(VECTRA_TNUM)
    det_descriptions = load_tnum_descriptions(MITRE_DESCRIPTIONS)
    malware_to_t_vectra_map = map_detections_mitre_techniques(malware_apl, TNUMBER_DETECTION_MAP, det_descriptions)

    malware_to_t_vectra_map['description'] = malware[0].get('description', '')
    response = app.response_class(
        response=json.dumps(malware_to_t_vectra_map),
        status=200,
        mimetype='application/json'
    )
    return response


@app.route('/api/get_tnum_info')
def get_tnum_info(tnum=None):
    """
    Supplied a MITRE T-number, returns a JSON property containing ['description', 'detections', 'error', 'groups',
    'phase', 'name', 'software', 'tnum']

    :param tnum: MITRE T-number
    :return : JSON property ['description', 'detections', 'error', 'groups', 'phase', 'name', 'software', 'tnum']
    """

    t_number = request.args.get('tnum').upper()

    # Retrieve technique
    try:
        technique = SRC.query([Filter("external_references.external_id", "=", t_number)])[0]
    except IndexError:
        response = app.response_class(
            response=json.dumps({'error': True}),
            status=200,
            mimetype='application/json'
        )
        return response

    name = technique.get('name', '')
    # Get t_number name, description
    description = technique.get('description', '')

    phase = technique.get('kill_chain_phases', '')[0]
    phase = phase.get('phase_name', '')

    # Get list of detections mapping to t_num
    detections = map_detection_technique2(TNUMBER_DETECTION_MAP, t_number)

    # Get list of groups utilizing t_num
    groups = list()
    # Get groups intrusion set
    groups_is = groups_using_technique(SRC)
    if groups_is.get(technique['id']):
        for group in groups_is.get(technique['id']):
            groups.append({'name': group['object']['name'], 'description': group['object']['description']})

    # Get list of software / tools mapping to t_num
    software = list()
    software_is = software_using_technique(SRC)
    if software_is.get(technique['id']):
        for tool in software_is.get(technique['id']):
            software.append({'name': tool['object']['name'], 'description': tool['object']['description']})

    response = app.response_class(
        response=json.dumps({
            "error": False,
            "tnum": t_number,
            "name": name,
            "phase": phase,
            "description": description,
            "detections": detections,
            "groups": groups,
            "software": software}),
        status=200,
        mimetype='application/json'
    )
    return response


'''
def main():
    set_logging('INFO')
    args = obtain_args()

    if len(sys.argv) == 1:
        print('Run: python3 mitre_storyboard.py -h for help.')
        sys.exit()

    src = load_mitre_data(ATTACK_DATA)

    if args.group:
        group_intrusion_set = get_group_by_alias(src, args.group)
        if len(group_intrusion_set) < 1:
            print('Group with name or alias [ {} ] not found.'.format(args.group))
            sys.exit(0)
        elif len(group_intrusion_set) > 1:
            print('{} groups found with name or alias'.format(len(group_intrusion_set)))

        group_apl = get_techniques_by_group_software(src, group_intrusion_set[0].get('id'))
        map_dict = load_detection_technique_json(VECTRA_TNUM)
        det_descriptions = load_tnum_descriptions(MITRE_DESCRIPTIONS)
        group_to_t_vectra_map = map_detections_mitre_techniques(group_apl, map_dict, det_descriptions)
        # pp = pprint.PrettyPrinter(indent=2)
        for k, v in group_to_t_vectra_map.items():
            print('{} : {}'.format(k, v))

    if args.malware:
        malware = get_malware_by_alias(src, args.malware)
        if len(malware) < 1:
            print('Malware with name or alias [ {} ] not found.  \nRefer to MITRE ATT&CK.'.format(args.malware))
            sys.exit(0)
        elif len(malware) > 1:
            print('{} malware found with name or alias'.format(len(malware)))

        malware_apl = get_techniques_by_software(techniques_used_by_software(src), malware[0].get('id'))
        map_dict = load_detection_technique_json(VECTRA_TNUM)
        det_descriptions = load_tnum_descriptions(MITRE_DESCRIPTIONS)
        malware_to_t_vectra_map = map_detections_mitre_techniques(malware_apl, map_dict, det_descriptions)
        for k, v in malware_to_t_vectra_map.items():
            print('{} : {}'.format(k, v))
'''

if __name__ == '__main__':
    app.run()

