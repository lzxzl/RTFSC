"""
CLE is an extensible binary loader. Its main goal is to take an executable program and any libraries it depends on and
produce an address space where that program is loaded and ready to run.

The primary interface to CLE is the Loader class.
"""

__version__ = (9, 0, "gitrolling")

if bytes is str: # 用于判断是否是python2，Python3 严格区分文本（str）和二进制数据（bytes），文本总是unicode，用str类型，二进制数据则用bytes类型表示；而Python2不区分，可以混用
    raise Exception("This module is designed for python 3 only. Please install an older version to use python 2.")

import logging
logging.getLogger(name=__name__).addHandler(logging.NullHandler())

# pylint: disable=wildcard-import
from . import utils
from .loader import *
from .memory import *
from .errors import *
from .backends import *
from .backends.tls import *
from .backends.externs import *
from .patched_stream import *
from .gdb import *
