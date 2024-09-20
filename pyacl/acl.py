"""
pyacl - high level abstractions over pylibacl
Copyright 2024, Georg Pfuetzenreuter <mail@georg-pfuetzenreuter.net>

Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European Commission - subsequent versions of the EUPL (the "Licence").
You may not use this work except in compliance with the Licence.
An English copy of the Licence is shipped in a file called LICENSE along with this applications source code.
You may obtain copies of the Licence in any of the official languages at https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12.
"""

from pwd import getpwnam, getpwuid

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


def parse_permission_string(strpermission):
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


def parse_entry_string(strentry):
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
      entryvalue: parse_permission_string(permissions),
    },
  }


def parse_acl(acl):  # noqa PLR0912, FIXME: uncomplexify this
  permap = {
    permission: False for permission in DEFAULT_PERMISSIONS.keys()
  }
  outmap = {
    group: {
      None: permap.copy(),
    } for group in DEFAULT_ENTRYTYPES
  }

  for entry in acl:
    name = None
    permset = entry.permset
    tag_type = entry.tag_type
    try:
      qualifier = entry.qualifier
    except TypeError:
      qualifier = None

    if tag_type == 0:
      return ValueError('Got ACL with undefined tag')

    if isinstance(qualifier, int):
      try:
        name = getpwuid(qualifier).pw_name
      except KeyError:
        name = qualifier
    elif qualifier is not None:
      return ValueError('Got ACL with unhandled qualifier')

    if tag_type in [ACL_USER, ACL_GROUP, ACL_USER_OBJ, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER]:
      for tag_high, tag_low in LIBACL_TAGS.items():
        if tag_low == tag_type:
          lowmap = permap.copy()
          for permission in lowmap.keys():
            lowmap[permission] = getattr(permset, permission)
          outtag = tag_high
          if tag_type == ACL_USER_OBJ:
            outname = None
            outtag = 'user'
          elif tag_type == ACL_GROUP_OBJ:
            outname = None
            outtag = 'group'
          else:
            outname = name
          if outtag not in outmap:
            outmap[outtag] = {}
          if len(outmap[outtag]) == 1 and list(outmap[outtag].keys())[0] is None:
            del outmap[outtag][None]
          outmap[outtag][outname] = lowmap
          break

  return outmap


def parse_acl_via_string(acl):
  outmap = {
    group: DEFAULT_PERMISSIONS for group in DEFAULT_ENTRYTYPES
  }

  for entry in acl:
    outmap.update(parse_entry_string(entry))

  return outmap


def build_acl(target_name, target_type, read=False, write=False, execute=False):
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


def apply_acl_to_path(acl, path):
  if acl.valid() is not True:
    return ValueError('ACL is not ready to be applied.')
  acl.applyto(path)


def read_acl_from_path(path):
  return ACL(file=path)


def parse_acl_from_path_via_string(path):
  return parse_acl_via_string(reduce_entries(read_acl_from_path(path)))


def parse_acl_from_path(path):
  return parse_acl(read_acl_from_path(path))
