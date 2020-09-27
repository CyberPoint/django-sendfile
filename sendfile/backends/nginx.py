from __future__ import absolute_import,unicode_literals
from builtins import bytes
import logging
from django.http import HttpResponse

from ._internalredirect import _convert_file_to_url

logger = logging.getLogger('django')

def sendfile(request, filename, **kwargs):
    response = HttpResponse()
    url = _convert_file_to_url(filename)

    logger.info( 'converted URL is {}'.format(url) )

    response['X-Accel-Redirect'] = bytes(url, 'utf-8').decode('utf-8', 'surrogateescape')

    logger.debug( response )
    logger.debug( response._headers )

    logger.info( "post converted URL is {}".format(response['X-Accel-Redirect']) )

    return response
