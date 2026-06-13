#!/usr/bin/env python3
# Menu generator for the AF3 ThoughtStream layer.
# Reads service.kodipersonal.setup/resources/config/lists.json and writes:
#   - skinvariables-shortcut-<slot>widgets.json  (one per section, AF3 format)
#   - slots.json  (slot name + toggle manifest for the setup service)
# into service.kodipersonal.setup/resources/menu/.
# The setup service deploys these onto each device.
#
# guids are derived deterministically from slot+path so regenerating the same
# lists.json produces identical files (stable byte-compare on the device).

import hashlib
import json
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADDON = os.path.join(REPO_ROOT, 'src', 'service.kodipersonal.setup', 'resources')
CONFIG = os.path.join(ADDON, 'config', 'lists.json')
OUT = os.path.join(ADDON, 'menu')


def guid_for(slot, path):
    h = hashlib.md5('{}|{}'.format(slot, path).encode('utf-8')).hexdigest()
    return 'guid-{}'.format(h[:8])


def widget(label, path):
    return {
        'label': label,
        'icon': '',
        'path': path,
        'target': 'videos',
        'guid': guid_for(label, path),
    }


def build():
    with open(CONFIG, 'r', encoding='utf-8') as fh:
        cfg = json.load(fh)

    base = cfg['tmdbh']
    suffix = cfg['widget_suffix']
    region = cfg['watch_region']
    monet = cfg['monetization']
    service_widgets = cfg['service_widgets']

    os.makedirs(OUT, exist_ok=True)
    slots_manifest = []

    for sec in cfg['sections']:
        slot = sec['slot']
        name = sec['name']
        rows = []

        if 'widgets' in sec:
            # Explicit widget list (For You)
            for w in sec['widgets']:
                path = '{}?info={}&tmdb_type={}{}'.format(
                    base, w['info'], w['tmdb_type'], suffix)
                rows.append(widget(w['label'], path))
        elif 'provider_id' in sec:
            # Service section: apply the shared service_widgets template
            pid = sec['provider_id']
            for w in service_widgets:
                path = ('{}?info=discover&tmdb_type={}'
                        '&with_watch_providers={}&watch_region={}'
                        '&with_watch_monetization_types={}&sort_by={}{}').format(
                    base, w['tmdb_type'], pid, region, monet, w['sort_by'], suffix)
                rows.append(widget(w['label'], path))

        fname = 'skinvariables-shortcut-{}widgets.json'.format(slot)
        with open(os.path.join(OUT, fname), 'w', encoding='utf-8') as fh:
            json.dump(rows, fh, indent=4)
        print('  wrote {} ({} widgets) for "{}"'.format(fname, len(rows), name))

        slots_manifest.append({'slot': slot, 'name': name, 'toggle': 'true'})

    with open(os.path.join(OUT, 'slots.json'), 'w', encoding='utf-8') as fh:
        json.dump(slots_manifest, fh, indent=4)
    print('  wrote slots.json ({} slots)'.format(len(slots_manifest)))


if __name__ == '__main__':
    print('Generating AF3 menu files...')
    build()
    print('Done.')
