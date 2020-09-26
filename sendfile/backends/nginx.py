from __future__ import absolute_import,unicode_literals

import logging
from django.http import HttpResponse

from ._internalredirect import _convert_file_to_url

logger = logging.getLogger('django')

def sendfile(request, filename, **kwargs):
    response = HttpResponse()
    url = _convert_file_to_url(filename)

    logger.info( 'converted URL is {}'.format(url) )

    response['X-Accel-Redirect'] = url.encode('utf-8')

    logger.debug( response )
    logger.debug( response._headers )

    response._headers['X-Accel-Redirect'] = url

    logger.info( "post converted URL is {}".format(response['X-Accel-Redirect']) )

    return response
