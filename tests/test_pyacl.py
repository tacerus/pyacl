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

  return list(data.items())


def load_yamls(file1, file2):
  data1 = load_yaml(file1)
  data2 = load_yaml(file2)

  out = []

  for lentry in data1:
    for i in range(len(lentry)):
      ix = i - 1
      out.append( ({'first': data1[ix], 'second': data2[ix]}) )  # noqa UP034, pytest mangles this in the parameters

  return out

@mark.parametrize('aclin, aclout', load_yaml('matrix.yaml'))
def test_parse_acl_through_string(sample_file_with_acl, aclin, aclout):
  have = acl.parse_acl_from_path_via_string(sample_file_with_acl)
  assert aclout == have


@mark.parametrize('aclin, aclout', load_yaml('matrix.yaml'))
def test_parse_acl_native(sample_file_with_acl, aclin, aclout):
  have = acl.parse_acl_from_path(sample_file_with_acl)
  assert aclout == have


@mark.parametrize('mode', ['fresh', 'update'])
@mark.parametrize('scenario, data', load_yaml('matrix-apply.yaml'))
def test_build_and_apply_acl(sample_file, mode, scenario, data):
  built_acl = acl.build_acl(**data['args'])
  assert len(list(built_acl)) == 5  # noqa PLR2004, this is the expected size of the built ACL
  assert acl.apply_acl_to_path(built_acl, sample_file) is None
  if mode == 'update':
    assert acl.update_acl_on_path(built_acl, sample_file) is None
  read_acl = acl.parse_acl_from_path(sample_file)
  assert read_acl == data['expect']


@mark.parametrize('data', load_yamls('matrix-apply.yaml', 'matrix-apply-update.yaml') )
def test_build_and_update_acl(sample_file, data):
  # we're updating the default instead of overwriting with apply
  # one better way would be to have both "before" and "after" in matrix-apply-update.yaml instead of re-using the one for apply
  # another would be to somehow adjust the apply map
  data['first'][1]['expect']['group'][None]['read'] = True
  data['first'][1]['expect']['other'][None]['read'] = True

  built_acl1 = acl.build_acl(**data['first'][1]['args'])
  assert len(list(built_acl1)) == 5  # noqa PLR2004, this is the expected size of the built ACL

  built_acl2 = acl.build_acl(**data['second'][1]['args'])
  assert len(list(built_acl2)) == 5  # noqa PLR2004

  assert acl.update_acl_on_path(built_acl1, sample_file) is None
  read_acl1 = acl.parse_acl_from_path(sample_file)
  assert read_acl1 == data['first'][1]['expect']

  assert acl.update_acl_on_path(built_acl2, sample_file) is None
  read_acl2 = acl.parse_acl_from_path(sample_file)
  assert read_acl2 == data['second'][1]['expect']
