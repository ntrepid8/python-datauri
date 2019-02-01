import base64
import mimetypes
import re
import textwrap

import six

# WARNING: The functions `base64.decodebytes` and `base64.encodebytes`
#          are sometimes monkey patched and can not be relied on to
#          produce an import error as a method of detecting Python 2
#          vs. Python 3.
# see: https://github.com/PythonCharmers/python-future
#      /blob/master/src/future/backports/xmlrpc/client.py#L137-L139

try:
    from urllib.parse import quote, unquote
except ImportError:
    from urllib import quote, unquote


from .exceptions import InvalidCharset, InvalidDataURI, InvalidMimeType


MIMETYPE_REGEX = r'[\w]+\/[\w\-\+\.]+'
_MIMETYPE_RE = re.compile('^{}$'.format(MIMETYPE_REGEX))

CHARSET_REGEX = r'[\w\-\+\.]+'
_CHARSET_RE = re.compile('^{}$'.format(CHARSET_REGEX))

DATA_URI_REGEX = (
    r'data:' +
    r'(?P<mimetype>{})?'.format(MIMETYPE_REGEX) +
    r"(?:\;name\=(?P<name>[\w\.\-%!*'~\(\)]+))?" +
    r'(?:\;charset\=(?P<charset>{}))?'.format(CHARSET_REGEX) +
    r'(?P<base64>\;base64)?' +
    r',(?P<data>.*)')
_DATA_URI_RE = re.compile(r'^{}$'.format(DATA_URI_REGEX), re.DOTALL)


class DataURI(str):

    @classmethod
    def make(cls, mimetype, charset, *args, **kwargs):
        # hacked to maintain backward compatibility with argument name that
        #  shadowed the standard lib base64 (sorry)

        # is_base64
        if len(args) > 0:
            is_base64 = args[0]
        elif 'base64' in kwargs:
            is_base64 = kwargs['base64']
        else:
            is_base64 = kwargs.get('is_base64', True)
        # data
        if len(args) > 1:
            data = args[1]
        else:
            data = kwargs['data']

        parts = ['data:']
        if mimetype is not None:
            if not _MIMETYPE_RE.match(mimetype):
                raise InvalidMimeType("Invalid mimetype: %r" % mimetype)
            parts.append(mimetype)
        if charset is not None:
            if not _CHARSET_RE.match(charset):
                raise InvalidCharset("Invalid charset: %r" % charset)
            parts.extend([';charset=', charset])
        if is_base64:
            parts.append(';base64')
            if six.PY3:
                _charset = charset or 'utf-8'
                if isinstance(data, bytes):
                    _data = data
                else:
                    _data = bytes(data, _charset)
                encoded_data = base64.encodebytes(_data).decode(_charset).strip()
            elif six.PY2:
                encoded_data = base64.encodestring(data).strip()
        else:
            encoded_data = quote(data)
        parts.extend([',', encoded_data])
        return cls(''.join(parts))

    @classmethod
    def from_file(cls, filename, charset=None, **kwargs):
        # hacked to maintain backward compatibility with argument name that
        #  shadowed the standard lib base64 (sorry)
        if 'base64' in kwargs:
            is_base64 = kwargs['base64']
        else:
            is_base64 = kwargs.get('is_base64', True)
        mimetype, _ = mimetypes.guess_type(filename, strict=False)
        with open(filename, 'rb') as fp:
            data = fp.read()

        return cls.make(mimetype, charset, is_base64, data)

    def __new__(cls, *args, **kwargs):
        uri = super(DataURI, cls).__new__(cls, *args, **kwargs)
        uri._parse  # Trigger any ValueErrors on instantiation.
        return uri

    def __repr__(self):
        return 'DataURI(%s)' % (super(DataURI, self).__repr__(),)

    def wrap(self, width=76):
        return '\n'.join(textwrap.wrap(self, width))

    @property
    def mimetype(self):
        return self._parse[0]

    @property
    def name(self):
        name = self._parse[1]
        if name is not None:
            return unquote(name)
        return name

    @property
    def charset(self):
        return self._parse[2]

    @property
    def is_base64(self):
        return self._parse[3]

    @property
    def data(self):
        return self._parse[4]

    @property
    def text(self):
        if self.charset is None:
            raise InvalidCharset("DataURI has no encoding set.")

        return self.data.decode(self.charset)

    @property
    def _parse(self):
        match = _DATA_URI_RE.match(self)
        if not match:
            raise InvalidDataURI("Not a valid data URI: %r" % self)
        mimetype = match.group('mimetype') or None
        name = match.group('name') or None
        charset = match.group('charset') or None

        if match.group('base64'):
            if six.PY3:
                _charset = charset or 'utf-8'
                _data = bytes(match.group('data'), _charset)
                data = base64.decodebytes(_data)
            elif six.PY2:
                data = base64.decodestring(match.group('data'))
        else:
            data = unquote(match.group('data'))

        return mimetype, name, charset, bool(match.group('base64')), data
