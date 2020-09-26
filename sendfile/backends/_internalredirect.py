from __future__ import unicode_literals
import logging
import os.path

from django.conf import settings
from django.utils.encoding import smart_text, smart_bytes

logger = logging.getLogger('django')

try:
    from urllib.parse import quote
except ImportError:
    from urllib import quote


def _convert_file_to_url(filename):
    logger.debug('converting {} to URL'.format(filename))
    relpath = os.path.relpath(filename, settings.SENDFILE_ROOT)
    logger.debug('relpath is {}'.format(relpath))
    url = [settings.SENDFILE_URL]

    while relpath:
        relpath, head = os.path.split(relpath)
        url.insert(1, head)

    logger.debug('URL is {}'.format(url))

    # Python3 urllib.parse.quote accepts both unicode and bytes, while Python2 urllib.quote only accepts bytes.
    # So use bytes for quoting and then go back to unicode.
    url = [url_component for url_component in url]
    return smart_text(quote('/'.join(url)))
