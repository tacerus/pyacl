"""
Test suite for pyacl
Copyright 2024, Georg Pfuetzenreuter <mail@georg-pfuetzenreuter.net>

Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European Commission - subsequent versions of the EUPL (the "Licence").
You may not use this work except in compliance with the Licence.
An English copy of the Licence is shipped in a file called LICENSE along with this applications source code.
You may obtain copies of the Licence in any of the official languages at https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12.
"""

from pyacl import acl


def test_parse_acl(sample_file):
  want = {
    'user': {
      'user': {
        'read': True,
        'write': False,
        'execute': False,
      },
    },
    'group': {
      None: {
        'read': True,
        'write': False,
        'execute': False,
      },
    },
    'mask': {
      None: {
        'read': True,
        'write': False,
        'execute': False,
      },
    },
    'other': {
      None: {
        'read': True,
        'write': False,
        'execute': False,
      },
    },
  }
  have = acl.parsefromfile(sample_file)
  assert want == have
