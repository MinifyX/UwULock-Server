#!/usr/bin/env python3
"""Writes the KeePass test files for src/lib/import/kdbx.test.ts, with pykeepass — an
implementation of its own, so the reader is checked against files it didn't write itself.

    python3 -m venv /tmp/kp && /tmp/kp/bin/pip install pykeepass
    /tmp/kp/bin/python src/lib/import/fixtures/make-kdbx.py [path/to/pykeepass/tests/test3.kdbx]

Not run by the tests. The key derivations are tiny (Argon2 with 1 MiB and 2 passes, AES-KDF
with 2000 rounds), so the tests stay fast; real files use far more. Everything in the files is
made up: the addresses are example.com/.net/.org, the secrets are the usual test vectors.
"""

import copy
import os
import sys

from construct import Container
from pykeepass import PyKeePass, create_database
from pykeepass.kdbx_parsing.kdbx4 import kdf_uuids

HERE = os.path.dirname(os.path.abspath(__file__))
PASSWORD = 'nyu-test-passwort'


def tune(kp, cipher, kdf, minor):
    """Cipher, KDF and version of the file; pykeepass keeps them when it saves."""
    header = kp.kdbx.header.value
    header.minor_version = minor
    header.dynamic_header.cipher_id.data = cipher
    params = header.dynamic_header.kdf_parameters.data.dict
    if kdf == 'aeskdf':
        # The blank file has Argon2's parameters; AES-KDF has a seed and rounds instead.
        for name in list(params):
            if name not in ('$UUID', 'S'):
                del params[name]
        params['$UUID'].value = kdf_uuids['aeskdf']
        # The dictionary ends after the item whose next byte is 0: that has to be the last one.
        params['S'].next_byte = 0x05
        params['R'] = Container(type=0x05, key='R', value=2000, next_byte=0)
    else:
        params['$UUID'].value = kdf_uuids[kdf]
        params['M'].value = 1024 * 1024
        params['I'].value = 2
        params['P'].value = 1


def history(entry, password):
    """An older version of the entry, with another password, in its history."""
    old = copy.deepcopy(entry._element)
    for child in old.findall('History'):
        old.remove(child)
    for value in old.xpath('String[Key="Password"]/Value'):
        value.text = password
    element = entry._element.find('History')
    if element is None:
        element = entry._element.makeelement('History')
        entry._element.append(element)
    element.append(old)


def personal():
    """Argon2id and ChaCha20, KDBX 4.0, a password only."""
    path = os.path.join(HERE, 'argon2id-chacha20.kdbx')
    kp = create_database(path, password=PASSWORD)
    tune(kp, 'chacha20', 'argon2id', 0)
    root = kp.root_group
    kp.add_entry(root, 'Router', 'admin', 'r0uter-pass', url='http://192.0.2.1')
    private = kp.add_group(root, 'Privat')
    banks = kp.add_group(private, 'Banken')
    mail = kp.add_entry(
        private,
        'Mail',
        'nyu@example.com',
        'mail-pass-1',
        url='https://mail.example.com',
        notes='Zweite Zeile\nfolgt hier',
        tags=['privat', 'wichtig'],
        otp='otpauth://totp/Mail:nyu@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Mail',
    )
    mail.set_custom_property('PIN', '1234', protect=True)
    mail.set_custom_property('Kundennummer', 'K-1001')
    mail.set_custom_property('KP2A_URL_1', 'https://webmail.example.net')
    mail.add_attachment(kp.add_binary(b'hallo', protected=True), 'hallo.txt')
    bank = kp.add_entry(banks, 'Bank', 'kunde-42', 'bank-pass-new', url='bank.example.org')
    history(bank, 'bank-pass-old')
    bank.set_custom_property('TimeOtp-Secret-Base32', 'GEZDGNBVGY3TQOJQ', protect=True)
    bank.set_custom_property('TimeOtp-Period', '60')
    kp.add_entry(root, 'WLAN-Notiz', '', '', notes='Gastnetz: nyu-gast')
    gone = kp.add_entry(root, 'Alt', 'old', 'old-pass')
    kp.trash_entry(gone)
    kp.save()
    check(path, PASSWORD, None)


def work():
    """AES-KDF and AES-256, KDBX 4.1, a password and a key file (XML, version 2.0)."""
    path = os.path.join(HERE, 'aeskdf-aes-keyfile.kdbx')
    keyfile = os.path.join(HERE, 'aeskdf-aes.keyx')
    kp = create_database(path, password=PASSWORD, keyfile=keyfile)
    tune(kp, 'aes256', 'aeskdf', 1)
    work = kp.add_group(kp.root_group, 'Arbeit')
    vpn = kp.add_entry(work, 'VPN', 'mika', 'vpn-pass', url='https://vpn.example.net')
    vpn.set_custom_property('TOTP Seed', 'JBSWY3DPEHPK3PXP', protect=True)
    vpn.set_custom_property('TOTP Settings', '30;8')
    vpn.set_custom_property('API-Token', 'tok-5678', protect=True)
    kp.save()
    check(path, PASSWORD, keyfile)


def legacy(template):
    """KDBX 3.1: AES-KDF, AES-256 and Salsa20 for the protected values, as KeePass 2 still writes
    it. pykeepass can't make a new 3.1 file, so this empties one of its own test files
    (tests/test3.kdbx, password "password", key file tests/test3.key) and fills it anew."""
    path = os.path.join(HERE, 'kdbx3-aes.kdbx')
    kp = PyKeePass(template, password='password', keyfile=template[: -len('.kdbx')] + '.key')
    root = kp.root_group
    for child in list(root._element):
        if child.tag in ('Group', 'Entry'):
            root._element.remove(child)
    meta = kp.tree.find('Meta')
    for name in ('HeaderHash', 'CustomIcons'):
        for child in meta.findall(name):
            meta.remove(child)
    for child in list(meta.find('Binaries')):
        meta.find('Binaries').remove(child)
    kp.password = PASSWORD
    kp.keyfile = None
    old = kp.add_group(root, 'Alt')
    entry = kp.add_entry(old, 'Forum', 'nyu', 'forum-pass', url='https://forum.example.org')
    entry.set_custom_property('Sicherheitsfrage', 'Blau', protect=True)
    entry.add_attachment(kp.add_binary(b'hallo', protected=True), 'hallo.txt')
    kp.add_entry(root, 'Drucker', 'print', 'print-pass', url='http://192.0.2.9')
    kp.save(path)
    check(path, PASSWORD, None)


def check(path, password, keyfile):
    kp = PyKeePass(path, password=password, keyfile=keyfile)
    header = kp.kdbx.header.value
    print(
        os.path.basename(path),
        f'KDBX {header.major_version}.{header.minor_version}',
        header.dynamic_header.cipher_id.data,
        len(kp.entries),
        'entries',
    )


if __name__ == '__main__':
    if not os.path.exists(os.path.join(HERE, 'aeskdf-aes.keyx')):
        sys.exit('aeskdf-aes.keyx is missing')
    personal()
    work()
    if len(sys.argv) > 1:
        legacy(sys.argv[1])
