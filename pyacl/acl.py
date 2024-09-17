"""
pyacl - high level abstractions over pylibacl
Copyright 2024, Georg Pfuetzenreuter <mail@georg-pfuetzenreuter.net>

Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European Commission - subsequent versions of the EUPL (the "Licence").
You may not use this work except in compliance with the Licence.
An English copy of the Licence is shipped in a file called LICENSE along with this applications source code.
You may obtain copies of the Licence in any of the official languages at https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12.
"""

from pwd import getpwnam

from posix1e import (
    ACL,
    ACL_GROUP,
    ACL_GROUP_OBJ,
    ACL_MASK,
    ACL_OTHER,
    ACL_USER,
    ACL_USER_OBJ,
)

DEFAULT_ENTRIES = [
  'u::rw-',
  'g::r--',
  'm::r--',
  'o::r--',
]

DEFAULT_PERMISSIONS = {
  'read': None,
  'write': None,
  'execute': None,
}

DEFAULT_ENTRYTYPES = [
  'user',
  'group',
  'mask',
  'other',
]

MAX_PERMBITS = 3

LIBACL_TAGS = {
  'user': ACL_USER,
  'group': ACL_GROUP,
  'user_obj': ACL_USER_OBJ,
  'group_obj': ACL_GROUP_OBJ,
  'other': ACL_OTHER,
  'mask': ACL_MASK,
}


def reduce_entries(acl):
  entries = acl.to_any_text().decode().split()
  entries = [entry for entry in entries if entry not in DEFAULT_ENTRIES]
  return entries


def parse_permission(strpermission):
  if len(strpermission) != MAX_PERMBITS:
    return ValueError('Invalid permission')

  permap_i = {
    0: 'read',
    1: 'write',
    2: 'execute',
  }

  permap_s = {
    'r': 'read',
    'w': 'write',
    'x': 'execute',
  }

  outmap = DEFAULT_PERMISSIONS.copy()

  for i, spval in enumerate(strpermission):
    permval = permap_i[i]
    if spval == '-':
      outmap[permval] = False
    else:
      spermval = permap_s.get(spval)
      if spermval and spermval in outmap:
        if spermval != permval:
          raise ValueError('Unexpected permission mismatch')
        outmap[spermval] = True
      else:
        return ValueError('Invalid permission flag')

  return outmap


def parse_entry(strentry):
  if not strentry:
    raise ValueError('Got empty string')

  entrytype, entryvalue, permissions = strentry.split(':')

  if entrytype not in DEFAULT_ENTRYTYPES:
    raise ValueError('Invalid entry')

  if entryvalue == '':
    entryvalue = None
  elif not entryvalue:
    return ValueError('Invalid entry value')

  if len(permissions) != MAX_PERMBITS:
    raise ValueError('Unsupported amount of permissions')

  return {
    entrytype: {
      entryvalue: parse_permission(permissions),
    },
  }


def parse_entries(acl):
  outmap = {
    group: DEFAULT_PERMISSIONS for group in DEFAULT_ENTRYTYPES
  }

  for entry in acl:
    outmap.update(parse_entry(entry))

  return outmap


def buildacl(target_name, target_type, read=False, write=False, execute=False):
  target_types = ['user', 'group']
  if target_type not in target_types or not isinstance(target_name, str):
    return ValueError('Invalid use of buildacl()')

  myacl = ACL()
  mytags = [tag for tag in LIBACL_TAGS if tag == target_type or tag in [ltag for ltag in LIBACL_TAGS if ltag not in target_types]]

  aclmap = {
    entry: myacl.append()
    for entry in mytags
  }

  for entry, reference in aclmap.items():
    reference.tag_type = LIBACL_TAGS[entry]

  aclmap[target_type].qualifier = getpwnam(target_name).pw_uid

  for pentry in ['mask', target_type]:
    perms = aclmap[pentry].permset
    perms.read = read
    perms.write = write
    perms.execute = execute

  return myacl


def acltofile(acl, path):
  if acl.valid() is not True:
    return ValueError('ACL is not ready to be applied.')
  acl.applyto(path)


def aclfromfile(path):
  return ACL(file=path)


def entriesfromfile(path):
  return reduce_entries(aclfromfile(path))


def parsefromfile(path):
  return parse_entries(reduce_entries(aclfromfile(path)))
