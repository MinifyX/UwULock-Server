#!/usr/bin/env python3
"""Writes the zip test files for src/lib/import/*.test.ts from the JSON next to them:
1password.1pux (export.data, export.attributes and a document under files/) and protonpass.zip
("Proton Pass/data.json"), both deflated as the apps write them. Not run by the tests.

    python3 src/lib/import/fixtures/make-zips.py
"""

import os
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))


def write(name, files):
    with zipfile.ZipFile(os.path.join(HERE, name), 'w', zipfile.ZIP_DEFLATED) as archive:
        for path, data in files:
            info = zipfile.ZipInfo(path, date_time=(2026, 9, 29, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)


def read(name):
    with open(os.path.join(HERE, name), 'rb') as file:
        return file.read()


write(
    '1password.1pux',
    [
        ('export.attributes', b'{"version":3,"description":"1Password Unencrypted Export"}'),
        ('export.data', read('1password-export.json')),
        ('files/d1__vertrag.pdf', b'%PDF-'),
    ],
)
write('protonpass.zip', [('Proton Pass/data.json', read('protonpass.json'))])
