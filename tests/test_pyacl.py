"""
Test suite for pyacl
Copyright 2024, Georg Pfuetzenreuter <mail@georg-pfuetzenreuter.net>

Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European Commission - subsequent versions of the EUPL (the "Licence").
You may not use this work except in compliance with the Licence.
An English copy of the Licence is shipped in a file called LICENSE along with this applications source code.
You may obtain copies of the Licence in any of the official languages at https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12.
"""

from os.path import dirname, join

from pytest import mark
from yaml import safe_load

from pyacl import acl


def load_yaml(file):
  with open(join(dirname(__file__), file)) as fh:
    data = safe_load(fh)

  out = []

  for entry in data:
    out.append(tuple(entry.items())[0])

  return out


@mark.parametrize('aclin, aclout', load_yaml('matrix.yaml'))
def test_parse_acl(sample_file, aclin, aclout):
  have = acl.parsefromfile(sample_file)
  assert aclout == have
