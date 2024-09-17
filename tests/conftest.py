"""
Helpers for the pyacl test suite
Copyright 2024, Georg Pfuetzenreuter <mail@georg-pfuetzenreuter.net>

Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European Commission - subsequent versions of the EUPL (the "Licence").
You may not use this work except in compliance with the Licence.
An English copy of the Licence is shipped in a file called LICENSE along with this applications source code.
You may obtain copies of the Licence in any of the official languages at https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12.
"""

from shutil import rmtree
from subprocess import run

import pytest


@pytest.fixture
def sample_file(tmp_path_factory):
  directory = tmp_path_factory.mktemp('sample_files')
  file = directory / 'file_to_be_acled'
  file.touch()
  assert not file.read_text()  # file should exist
  yield file
  rmtree(directory)


@pytest.fixture
def sample_file_with_acl(tmp_path_factory, aclin):
  directory = tmp_path_factory.mktemp('sample_files')
  file = directory / 'file_with_user_read_acl'
  file.touch()
  assert not file.read_text()  # file should exist
  requested_acl = aclin
  print(requested_acl)
  run(['setfacl', '-m', requested_acl, file], check=True)
  out = run(['getfacl', '-c', file], check=True, capture_output=True)
  assert requested_acl in out.stdout.decode()  # file should have the ACL set
  yield file
  rmtree(directory)
