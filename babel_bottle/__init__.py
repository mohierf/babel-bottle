#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""
Babel extractor for Bottle templates
"""
# Application manifest
VERSION = (0, 1, 1)

__application__ = u"Babel Bottle"
__version__ = '.'.join((str(each) for each in VERSION[:4]))
__author__ = u"Frederic Mohier"
__copyright__ = u"(c) 2015 - %s" % __author__
__license__ = u"GNU Affero General Public License, version 3"
__description__ = u"Babel extractor for Bottle templates"
__releasenotes__ = u"""Alignak backend client library"""
__doc_url__ = "https://github.com/mohierf/babel-bottle.git"
# Application manifest
manifest = {
    'name': __application__,
    'version': __version__,
    'author': __author__,
    'description': __description__,
    'copyright': __copyright__,
    'license': __license__,
    'release': __releasenotes__,
    'doc': __doc_url__
}

from babel_bottle import extract_tpl