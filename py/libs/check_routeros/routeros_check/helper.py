# SPDX-FileCopyrightText: PhiBo DinoTools (2021)
# SPDX-License-Identifier: GPL-3.0-or-later
# Modified by sepehr.ha@gmail.com
import importlib
import logging
import os
import re
from typing import List, Optional

logger = logging.getLogger('nagiosplugin')


REGEX_VERSION_PATTERN = r"""
    (?P<release>[0-9]+(?:\.[0-9]+)*)
    (?P<pre>
        [-_\.]?
        (?P<pre_type>(a|b|c|rc|alpha|beta|pre|preview))
        [-_\.]?
        (?P<pre_serial>[0-9]+)?
    )?
"""


class RouterOSVersion(object):
    def __init__(self, version_string: str):
        regex = re.compile(r"^\s*" + REGEX_VERSION_PATTERN + r"\s*$", re.VERBOSE | re.IGNORECASE)
        m = regex.match(version_string)
        if not m:
            raise ValueError(f"Unable to parse version string: '{version_string}'")

        self.release = tuple([int(v) for v in m.group("release").split(".")])
        self.pres = m.group("pre")
        if not self.pres:
            self.pres =""
        
        # At the moment we don't handle the pre releases like alpha, beta or rc
        # We should try to work with major and minor version

        self._cmp_attribute_names = ("major", "minor", "patch")
        self._cmp_pre_names = ("pre")

    def __eq__(self, other):
        for attr_name in self._cmp_attribute_names:
            if getattr(self, attr_name) != getattr(other, attr_name):
                return False
            if getattr(self, "pre") != getattr(other, "pre"):
                return False
        return True

    def __ge__(self, other):
        return self > other or self == other

    def __gt__(self, other):
        for attr_name in self._cmp_attribute_names:
            if getattr(self, attr_name) > getattr(other, attr_name):
                return True
            if getattr(self, attr_name) < getattr(other, attr_name):
                return False
        if getattr(self, "pre") > getattr(other, "pre"):
            return True
        if getattr(self, "pre") < getattr(other, "pre"):
                return False
        return False

    def __le__(self, other):
        return self < other or self == other

    def __lt__(self, other):
        for attr_name in self._cmp_attribute_names:
            if getattr(self, attr_name) < getattr(other, attr_name):
                return True
            if getattr(self, attr_name) > getattr(other, attr_name):
                return False
        if getattr(self, "pre") < getattr(other, "pre"):
            return True
        if getattr(self, "pre") > getattr(other, "pre"):
                return False
        return False

    def __repr__(self):
        return f"{self.__class__.__name__}('{self}')"

    def __str__(self):
        return f"{'.'.join([str(v) for v in self.release])}" + self.pres

    @property
    def major(self) -> int:
        return self.release[0] if len(self.release) >= 1 else 0

    @property
    def minor(self) -> int:
        return self.release[1] if len(self.release) >= 2 else 0

    @property
    def patch(self) -> int:
        return self.release[2] if len(self.release) >= 3 else 0
    
    @property
    def pre(self) -> int:
        if self.pres is not None and self.pres.strip()!='':
            var = self.pres
        else:
            var = "0"
        return int(''.join(c for c in var if c.isdigit()))
    
def escape_filename(value):
    value = re.sub(r"[^\w\s-]", "_", value).strip().lower()
    return re.sub(r"[-\s]+", '-', value)


def load_modules(pkg_names: Optional[List] = None):
    if pkg_names is None:
        pkg_names = [".check"]
    for base_pkg_name in pkg_names:
        logger.debug("Base package name: %s", base_pkg_name)
        base_pkg = importlib.import_module(base_pkg_name, package=__package__)

        logger.debug("Base package: %s", base_pkg)

        path = base_pkg.__path__[0]
        logger.debug("Base path: %s", path)

        for filename in os.listdir(path):
            if filename == "__init__.py":
                continue

            pkg_name = None
            if os.path.isdir(os.path.join(path, filename)) and \
                    os.path.exists(os.path.join(path, filename, "__init__.py")):
                pkg_name = filename

            if filename[-3:] == '.py':
                pkg_name = filename[:-3]

            if pkg_name is None:
                continue

            mod_name = "{}.{}".format(base_pkg_name, pkg_name)
            try:
                importlib.import_module(mod_name, package=__package__)
                logger.info("Loaded '%s' successfully", mod_name)
            except ImportError:
                logger.warning("Unable to load: '%s'", mod_name)
                logger.debug("An error occurred while importing '%s'", mod_name, exc_info=True)
