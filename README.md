# pyacl

## Overview

This is a high level abstraction over the great [pylibacl](https://pylibacl.k1024.org/) library.
It removes the need for low level understanding of POSIX.1e by providing an interface similar to what one is used to by common ACL handling tools such as `getfacl(1)` and `setfacl(1)`. Handling of ACLs in `pyacl` happens through a map resembling what one would find as a result of calling `getfacl(1)`.

## Example

### Reading the ACL of a path

The following shows a file at `/tmp/testacl1` on which an ACL granting the user `georg2` read permissions was applied.

#### Result from `getfacl(1)`:

```
$ getfacl -c /tmp/testacl1
getfacl: Removing leading '/' from absolute path names
user::---
user:georg2:r--
group::r--
mask::r--
other::---
```

#### Result from `pyacl`:

```
>>> from pyacl import acl
>>> acl.parse_acl_from_path('/tmp/testacl1')
{'user': {'georg2': {'read': True, 'write': False, 'execute': False}},
 'group': {None: {'read': True, 'write': False, 'execute': False}},
 'mask': {None: {'read': True, 'write': False, 'execute': False}},
 'other': {None: {'read': False, 'write': False, 'execute': False}}}
```

### Writing an ACL to a path

The following will apply ACL granting the user `georg2` read permissions to a file at `/tmp/testacl2`.

```
echo hi > /tmp/testacl2
```

#### With `setfacl(1)`:

```
setfacl -m u:georg2:r /tmp/testacl2
```

#### With `pyacl`:

```
>>> from pyacl import acl
>>> myacl = acl.build_acl(target_name='georg2', target_type='user', read=True, write=False, execute=False)
>>> acl.apply_acl_to_path(myacl, '/tmp/testacl2')
```

Of course, the `build_acl()` call could be shortened by omitting default arguments.

## Documentation

The functions provided by `pyacl` are documented through docstrings. Find them in the source code, or by calling `help()` - example:

```
>>> from pyacl import acl
>>> help(acl.build_acl)
Help on function build_acl in module pyacl.acl:

build_acl(target_name, target_type, read=False, write=False, execute=False)
    Example usage: build_acl(target_name='georg2', target_type='user', read=True, write=False, execute=True)
    Return: posix1e.ACL
```

## Hacking/Tests

Functionality is tested through `pytest`. As it requires a certain test user to be present, easiest is to use the purpose-built container image. A wrapper is provided at `test.sh`.
