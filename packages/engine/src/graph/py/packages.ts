import { normalizePyName } from '../../inventory/python.ts';

/** Import module name -> PyPI distribution, where they differ beyond PEP 503 normalisation. */
const MODULE_TO_DIST: Record<string, string> = {
  yaml: 'pyyaml',
  PIL: 'pillow',
  sklearn: 'scikit-learn',
  bs4: 'beautifulsoup4',
  dateutil: 'python-dateutil',
  cv2: 'opencv-python',
  Crypto: 'pycryptodome',
  jwt: 'pyjwt',
  rest_framework: 'djangorestframework',
  OpenSSL: 'pyopenssl',
  google: 'protobuf',
  MySQLdb: 'mysqlclient',
  psycopg2: 'psycopg2-binary',
  dotenv: 'python-dotenv',
  magic: 'python-magic',
  jose: 'python-jose',
  multipart: 'python-multipart',
  attr: 'attrs',
  pkg_resources: 'setuptools',
  gi: 'pygobject',
  serial: 'pyserial',
  usb: 'pyusb',
  wx: 'wxpython',
  Levenshtein: 'python-levenshtein',
  docx: 'python-docx',
  pptx: 'python-pptx',
  markdown: 'markdown',
  jinja2: 'jinja2',
  werkzeug: 'werkzeug',
  flask: 'flask',
  django: 'django',
  fastapi: 'fastapi',
  starlette: 'starlette',
  sqlalchemy: 'sqlalchemy',
  requests: 'requests',
  urllib3: 'urllib3',
  cryptography: 'cryptography',
  lxml: 'lxml',
  paramiko: 'paramiko',
  pydantic: 'pydantic',
  aiohttp: 'aiohttp',
  httpx: 'httpx',
  celery: 'celery',
  redis: 'redis',
  boto3: 'boto3',
};

const STDLIB = new Set(['os', 'sys', 're', 'json', 'time', 'datetime', 'math', 'random', 'typing', 'pathlib', 'collections', 'functools', 'itertools', 'logging', 'subprocess', 'threading', 'asyncio', 'io', 'uuid', 'hashlib', 'hmac', 'base64', 'secrets', 'string', 'struct', 'copy', 'enum', 'dataclasses', 'abc', 'contextlib', 'decimal', 'fractions', 'glob', 'shutil', 'tempfile', 'urllib', 'http', 'email', 'html', 'xml', 'csv', 'sqlite3', 'socket', 'ssl', 'select', 'signal', 'pickle', 'shelve', 'zlib', 'gzip', 'tarfile', 'zipfile', 'unittest', 'argparse', 'configparser', 'traceback', 'warnings', 'inspect', 'importlib', 'types', 'operator', 'statistics', 'textwrap', 'unicodedata', 'binascii', 'codecs', 'queue', 'heapq', 'bisect', 'array', 'weakref', 'gc', 'platform', 'getpass', 'locale', 'calendar', 'pprint', 'numbers', 'mimetypes', 'smtplib', 'ftplib', 'imaplib', 'wsgiref', 'cgi', 'tkinter', 'builtins', '__future__']);

/** PyPI distribution (normalised) for a top-level import, or undefined for the standard library / local code. */
export function distForModule(topLevel: string, installed: Set<string>): string | undefined {
  if (STDLIB.has(topLevel)) return undefined;
  const mapped = MODULE_TO_DIST[topLevel];
  if (mapped && installed.has(mapped)) return mapped;
  const norm = normalizePyName(topLevel);
  if (installed.has(norm)) return norm;
  // flask_login -> flask-login, django_filters -> django-filter(s)
  if (installed.has(norm.replace(/s$/, ''))) return norm.replace(/s$/, '');
  if (mapped) return mapped;
  return undefined;
}
