#!/usr/bin/env python3
# =============================================================================
# IMPLEMENTATION B -- Python 3, standard library ONLY.
#
# Written from the normative specification text. It shares no code with
# implementation A (proof/impl-node/assurance.cjs) and no code with the kit's
# lib/. It does not import `cryptography`, `nacl`, or any other package:
# Ed25519 verification is implemented here from RFC 8032 in pure integer
# arithmetic, so the differential test crosses two UNRELATED crypto stacks
# (OpenSSL on the Node side, this file on the Python side) rather than two
# callers of the same one.
#
# Normative sources (pinned in proof/SOURCE_PINS.json):
#   [S1] x402#3220 authority.md  §3 shape, §4 tags, §5 digest, §6 authorize,
#        §7 preimage binding.
#   [S3] vauban-org/x402-starknet docs/stark-receipt-profile-v0.1.md
#        §2.1, §2.2, §4.1, §4.2, §4.3, §4.5, §4.6, §5.
#   [S4] STILLOS_NOTARY_RECEIPT_V1.md
#   [S5] RFC 8785 (JCS), RFC 8032 (Ed25519), FIPS 180-4 (SHA-256 via hashlib).
#
# hashlib is used for SHA-256/SHA-512. Re-deriving SHA-256 itself would test
# CPython's hashlib against OpenSSL, which is not the property under test and
# is declared as such in PROOF.md rather than quietly assumed.
# =============================================================================

import base64
import hashlib
import json
import re
import sys

# -----------------------------------------------------------------------------
# RFC 8032 Ed25519 verification, from scratch.  [S5]
# -----------------------------------------------------------------------------
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _recover_x(y, sign):
    """RFC 8032 5.1.3 -- recover x from the compressed y and its sign bit."""
    if y >= _P:
        return None
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if (x * x - xx) % _P != 0:
        return None            # not on the curve
    if (x & 1) != sign:
        x = _P - x
    return x


# Extended twisted-Edwards coordinates (X, Y, Z, T), so verification stays
# fast enough to run thousands of property cases without a native library.
def _point_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (2 * t1 * t2 * _D) % _P
    d = (2 * z1 * z2) % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return ((e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P)


def _scalar_mul(p, e):
    q = (0, 1, 1, 0)           # neutral element
    while e > 0:
        if e & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        e >>= 1
    return q


_BY = (4 * pow(5, _P - 2, _P)) % _P
_BX = _recover_x(_BY, 0)
_B = (_BX, _BY, 1, (_BX * _BY) % _P)


def _point_equal(p, q):
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def _decode_point(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, 'little')
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % _P)


def ed25519_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """RFC 8032 5.1.7. Returns False on any malformed input -- never raises."""
    try:
        if len(signature) != 64 or len(public_key) != 32:
            return False
        a = _decode_point(public_key)
        if a is None:
            return False
        r = _decode_point(signature[:32])
        if r is None:
            return False
        s = int.from_bytes(signature[32:], 'little')
        if s >= _L:            # 5.1.7 step 1: reject non-canonical S
            return False
        k = int.from_bytes(
            hashlib.sha512(signature[:32] + public_key + message).digest(),
            'little') % _L
        # Check [S]B == R + [k]A
        return _point_equal(_scalar_mul(_B, s), _point_add(r, _scalar_mul(a, k)))
    except Exception:
        return False


# -----------------------------------------------------------------------------
# RFC 8785 JCS  [S5]
# -----------------------------------------------------------------------------
class JcsError(Exception):
    pass


def _utf16_units(s):
    """RFC 8785 3.2.3 sorts object keys as sequences of UTF-16 CODE UNITS.

    Python strings are sequences of code POINTS, and the two orderings differ:
    an astral character (U+10000..U+10FFFF) encodes to a surrogate pair
    (0xD800..0xDFFF) and therefore sorts BEFORE U+E000..U+FFFF under UTF-16,
    but AFTER them under code-point ordering. Sorting with Python's default
    `sorted()` is therefore WRONG for keys outside the BMP. This is a real
    divergence between the two implementations if it is not handled, which is
    exactly why the adversarial corpus carries a case for it.
    """
    return tuple(int.from_bytes(s.encode('utf-16-be')[i:i + 2], 'big')
                 for i in range(0, len(s.encode('utf-16-be')), 2))


_ESCAPES = {0x08: '\\b', 0x09: '\\t', 0x0a: '\\n', 0x0c: '\\f',
            0x0d: '\\r', 0x22: '\\"', 0x5c: '\\\\'}


def _jcs_string(s):
    out = ['"']
    for ch in s:
        c = ord(ch)
        if c in _ESCAPES:
            out.append(_ESCAPES[c])
        elif c < 0x20:
            out.append('\\u%04x' % c)
        else:
            out.append(ch)
    out.append('"')
    return ''.join(out)


def _is_well_formed(s):
    """A lone surrogate cannot be encoded to UTF-8; JCS output is UTF-8."""
    try:
        s.encode('utf-8')
        return True
    except UnicodeEncodeError:
        return False


def jcs(value):
    if value is None:
        return 'null'
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if isinstance(value, str):
        if not _is_well_formed(value):
            raise JcsError('jcs_lone_surrogate')
        return _jcs_string(value)
    if isinstance(value, int):
        # SCOPE CUT, stated not hidden -- see the matching note in
        # implementation A. Every numeric field in [S1] §4 and [S3] §4.6 is a
        # decimal STRING; non-integer numbers are refused, not approximated.
        if abs(value) > 2 ** 53 - 1:
            raise JcsError('jcs_unsafe_integer')
        return str(value)
    if isinstance(value, float):
        if value.is_integer() and abs(value) <= 2 ** 53 - 1:
            return str(int(value))
        raise JcsError('jcs_non_integer_number_out_of_profile')
    if isinstance(value, list):
        return '[' + ','.join(jcs(v) for v in value) + ']'
    if isinstance(value, dict):
        keys = sorted(value.keys(), key=_utf16_units)
        return '{' + ','.join(_jcs_string(k) + ':' + jcs(value[k]) for k in keys) + '}'
    raise JcsError('jcs_unsupported_type_' + type(value).__name__)


def sha256hex(b):
    if isinstance(b, str):
        b = b.encode('utf-8')
    return hashlib.sha256(b).hexdigest()


# -----------------------------------------------------------------------------
# STILLOS_NOTARY_RECEIPT_V1  [S4]
# -----------------------------------------------------------------------------
NOTARY_FIELD_ORDER = ['agent', 'claim_sha256', 'ts', 'prev_hash', 'notary_fp', 'resolver_hash']


def notary_preimage(receipt):
    """Fixed field ORDER + compact JSON. NOT JCS: JCS would sort the keys
    alphabetically ('agent','claim_sha256','notary_fp','prev_hash',...) and
    produce a different digest. `resolver_hash` is OMITTED, not null, on a
    claim receipt."""
    parts = []
    for f in NOTARY_FIELD_ORDER:
        if f == 'resolver_hash' and 'resolver_hash' not in receipt:
            continue
        if f not in receipt:
            raise ValueError('notary_missing_field_' + f)
        parts.append(_jcs_string(f) + ':' + jcs(receipt[f]))
    return '{' + ','.join(parts) + '}'


def raw_pub_from_pem(pem):
    body = re.sub(r'-----(BEGIN|END) PUBLIC KEY-----', '', pem)
    der = base64.b64decode(re.sub(r'\s+', '', body))
    if len(der) != 44:
        raise ValueError('unexpected_spki_length_%d' % len(der))
    return der[12:]


def notary_verify(receipt, raw_pub32):
    preimage = notary_preimage(receipt)
    computed = sha256hex(preimage)
    sig_ok = False
    sig_error = None
    try:
        # [S4]: signed over the UTF-8 bytes of the 64-char hex STRING, not the
        # 32 raw digest bytes.
        sig_ok = ed25519_verify(receipt['receipt_hash'].encode('utf-8'),
                                base64.b64decode(receipt['signature']),
                                raw_pub32)
    except Exception as e:                       # noqa: BLE001
        sig_error = str(e)
    return {
        'preimage': preimage,
        'field_count': 0 if preimage == '{}' else preimage.count('","') + 1,
        'computed_hash': computed,
        'hash_ok': computed == receipt.get('receipt_hash'),
        'sig_ok': sig_ok,
        'sig_error': sig_error,
    }


# -----------------------------------------------------------------------------
# Vauban §2.1 digest triple  [S3]
# -----------------------------------------------------------------------------
KNOWN_ALG = {'sha-256', 'keccak-256', 'poseidon-252', 'blake2s-256'}
KNOWN_ENC = {'none', 'felt252-masked-251'}
MASK_251 = (1 << 251) - 1


def digest_triple(t):
    if not isinstance(t, dict):
        return {'valid': False, 'error': 'not_an_object'}
    if 'alg' not in t:
        return {'valid': False, 'error': 'missing_alg'}
    if 'enc' not in t:                    # §2.1: invalid, NOT defaulted
        return {'valid': False, 'error': 'missing_enc'}
    if 'hex' not in t:
        return {'valid': False, 'error': 'missing_hex'}
    if t['alg'] not in KNOWN_ALG:
        return {'valid': False, 'error': 'unknown_alg'}
    if t['enc'] not in KNOWN_ENC:
        return {'valid': False, 'error': 'unknown_enc'}
    if not isinstance(t['hex'], str):
        return {'valid': False, 'error': 'hex_not_a_string'}
    bare = t['hex'][2:] if t['hex'][:2].lower() == '0x' else t['hex']
    if len(bare) == 0 or re.fullmatch(r'[0-9a-fA-F]*', bare) is None:
        return {'valid': False, 'error': 'hex_not_hex'}
    if len(bare) != 64:
        return {'valid': False, 'error': 'bad_hex_length'}
    if bare != bare.lower():
        return {'valid': False, 'error': 'hex_not_lowercase'}
    d = int(bare, 16)
    stored = (d & MASK_251) if t['enc'] == 'felt252-masked-251' else d
    return {
        'valid': True,
        'alg': t['alg'],
        'enc': t['enc'],
        'full_hex': '0x' + bare,
        # §2.2: compare as integers, render one form (lowercase, 0x, no
        # leading zero).
        'comparison_hex': '0x' + format(stored, 'x'),
        'comparison_decimal': str(stored),
        'top5bits': d >> 251,
        'masking_is_noop': stored == d,
        'full_equals_stored': stored == d,
    }


def digest_limbs(hex64):
    bare = hex64[2:] if hex64[:2] == '0x' else hex64
    if re.fullmatch(r'[0-9a-f]{64}', bare) is None:
        raise ValueError('expected_64_lowercase_hex')
    d = int(bare, 16)
    lo, hi = d % (1 << 128), d >> 128     # §4.2 low then high, lossless
    return {
        'digest_D_decimal': str(d),
        'digest_lo': str(lo), 'digest_hi': str(hi),
        'digest_lo_hex': '0x' + format(lo, 'x'),
        'digest_hi_hex': '0x' + format(hi, 'x'),
    }


def limbs_to_hex(lo_s, hi_s):
    lo, hi = int(lo_s), int(hi_s)
    if not 0 <= lo < (1 << 128):
        raise ValueError('digest_lo_out_of_u128_range')
    if not 0 <= hi < (1 << 128):
        raise ValueError('digest_hi_out_of_u128_range')
    return format(hi * (1 << 128) + lo, '064x')


def origin_tag_felt(tag):
    """§4.1 -- a Cairo short string, at most 31 ASCII bytes packed in a felt252."""
    if not isinstance(tag, str):
        return {'ok': False, 'error': 'tag_not_a_string'}
    b = tag.encode('utf-8')
    if len(b) > 31:
        return {'ok': False, 'error': 'tag_over_31_bytes'}
    if any(x > 0x7f for x in b):
        return {'ok': False, 'error': 'tag_not_ascii'}
    v = 0
    for x in b:
        v = (v << 8) | x
    return {'ok': True, 'felt_decimal': str(v), 'felt_hex': '0x' + format(v, 'x'),
            'byte_length': len(b)}


def v3_batch_check(k, leaves):
    """§4.3 -- the four named refusals plus the two settled edge cases."""
    if not isinstance(leaves, list):
        return {'provable': False, 'refusals': ['MALFORMED_LEAVES']}
    refusals = []
    f = len(leaves)
    if f > 64:
        refusals.append('F4')
    if k == 0 and f == 0:
        refusals.append('K0F0')
    seen = set()
    for i, lf in enumerate(leaves):
        tag = origin_tag_felt(lf.get('origin_tag'))
        if not tag['ok'] or tag['felt_decimal'] == '0':
            refusals.append('F1@%d' % i)
        lo = int(lf.get('digest_lo') or '0')
        hi = int(lf.get('digest_hi') or '0')
        if lo == 0 and hi == 0:
            refusals.append('F2@%d' % i)
        key = '%s|%s|%s' % (lf.get('origin_tag'), lf.get('digest_lo'), lf.get('digest_hi'))
        if key in seen:
            refusals.append('F3@%d' % i)
        seen.add(key)
    return {
        'provable': len(refusals) == 0,
        'refusals': refusals,
        'K': k, 'F': f,
        'root_domain_tag': 'VZKPAY_AGGROOT_V3',     # §4.5
        'pure_leaf_batch': k == 0 and f >= 1,       # legal per §4.3
    }


# §4.6 BASE_SETTLEMENT_V1
BASE_SETTLEMENT_FIELDS = ['amount', 'asset', 'network', 'payTo', 'payer', 'resource', 'transaction']
BASE_SETTLEMENT_HEX_FIELDS = ['asset', 'payTo', 'payer', 'transaction']


def base_settlement_v1(obj):
    if not isinstance(obj, dict):
        return {'valid': False, 'error': 'not_an_object'}
    for f in BASE_SETTLEMENT_FIELDS:
        if f not in obj:
            return {'valid': False, 'error': 'missing_field_' + f}
    for k in obj:                       # "...of seven fields, and of nothing else"
        if k not in BASE_SETTLEMENT_FIELDS:
            return {'valid': False, 'error': 'unknown_field_' + k}
    for f in BASE_SETTLEMENT_FIELDS:    # "The values are STRINGS"
        if not isinstance(obj[f], str):
            return {'valid': False, 'error': 'field_not_a_string_' + f}
    if re.fullmatch(r'0|[1-9][0-9]*', obj['amount']) is None:
        return {'valid': False, 'error': 'amount_not_canonical_decimal'}
    # "The four hex fields are lowercase" -- the profile does not enumerate
    # which four; asset/payTo/payer/transaction are the only hex-valued ones.
    # Recorded as an INFERENCE in PROOF.md, not as spec text.
    for f in BASE_SETTLEMENT_HEX_FIELDS:
        if re.fullmatch(r'0x[0-9a-f]+', obj[f]) is None:
            return {'valid': False, 'error': 'hex_field_not_lowercase_0x_' + f}
    # "network keeps its case, a CAIP-2 reference being case-sensitive"
    if re.fullmatch(r'[-a-zA-Z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}', obj['network']) is None:
        return {'valid': False, 'error': 'network_not_caip2'}
    canonical = jcs(obj)
    return {'valid': True, 'jcs': canonical, 'digest_hex': sha256hex(canonical)}


# -----------------------------------------------------------------------------
# x402#3220 authority -- §3/§4/§5/§6/§7, implemented from the spec text.  [S1]
# -----------------------------------------------------------------------------
MANDATE_TAG = b'x402-mandate/1\n'
BINDING_TAG = b'x402-mandate-binding/1\n'
AMOUNT_RE = re.compile(r'0|[1-9][0-9]*')
KEY_RE = re.compile(r'[A-Za-z0-9_-]{43}')
SIG_RE = re.compile(r'[A-Za-z0-9_-]{86}')
TIMESTAMP_RE = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z')
PAYMENT_ID_RE = re.compile(r'[A-Za-z0-9._~-]{1,64}')
MANDATE_DIGEST_RE = re.compile(r'sha256:[0-9a-f]{64}')
MANDATE_MEMBERS = {'v', 'issuer', 'subject', 'asset', 'cap', 'perPayment',
                   'recipients', 'accountant', 'purpose', 'notAfter', 'nonce', 'parent'}
REQUIRED_MEMBERS = ['v', 'issuer', 'subject', 'asset', 'cap', 'recipients',
                    'accountant', 'purpose', 'notAfter', 'nonce']


def _b64url_decode(s):
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def _strict_timestamp(ts):
    """§3: shape-valid but overflowing dates (…-02-30…) are INVALID. Must
    survive a round trip; lenient normalizing parsers MUST NOT be relied on."""
    m = re.fullmatch(r'(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,3})?Z', ts)
    if m is None:
        return None
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    try:
        import datetime
        dt = datetime.datetime(y, mo, d, h, mi, s, tzinfo=datetime.timezone.utc)
    except ValueError:
        return None
    if (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second) != (y, mo, d, h, mi, s):
        return None
    ms = int((m.group(7) or '.0')[1:].ljust(3, '0'))
    return int(dt.timestamp()) * 1000 + ms


def validate_mandate_shape(m):
    if not isinstance(m, dict):
        return {'ok': False, 'code': 'malformed_input'}
    for k in m:
        if k not in MANDATE_MEMBERS:
            return {'ok': False, 'code': 'invalid_bundle'}
    for k in REQUIRED_MEMBERS:
        if k not in m:
            return {'ok': False, 'code': 'invalid_bundle'}
    if m['v'] != 'x402-mandate/1':
        return {'ok': False, 'code': 'unsupported_version'}
    str_fields = ['issuer', 'subject', 'asset', 'cap', 'accountant', 'purpose',
                  'notAfter', 'nonce']
    for f in str_fields:
        if not isinstance(m[f], str):
            return {'ok': False, 'code': 'invalid_bundle'}
        if not _is_well_formed(m[f]):          # §3 UTF-16 well-formedness
            return {'ok': False, 'code': 'invalid_bundle'}
    if 'parent' in m and (not isinstance(m['parent'], str)
                          or re.fullmatch(r'sha256:[0-9a-f]{64}', m['parent']) is None):
        return {'ok': False, 'code': 'invalid_bundle'}
    if KEY_RE.fullmatch(m['issuer']) is None:
        return {'ok': False, 'code': 'invalid_bundle'}
    if AMOUNT_RE.fullmatch(m['cap']) is None:
        return {'ok': False, 'code': 'invalid_bundle'}
    if 'perPayment' in m:
        if not isinstance(m['perPayment'], str) or AMOUNT_RE.fullmatch(m['perPayment']) is None:
            return {'ok': False, 'code': 'invalid_bundle'}
        if int(m['perPayment']) > int(m['cap']):
            return {'ok': False, 'code': 'invalid_bundle'}
    r = m['recipients']
    if not isinstance(r, list) or len(r) == 0:
        return {'ok': False, 'code': 'invalid_bundle'}
    for e in r:
        if not isinstance(e, str) or not _is_well_formed(e):
            return {'ok': False, 'code': 'invalid_bundle'}
    if '*' in r and len(r) != 1:               # "*" mixed with anything is INVALID
        return {'ok': False, 'code': 'invalid_bundle'}
    if m['accountant'] != 'payees' and KEY_RE.fullmatch(m['accountant']) is None:
        return {'ok': False, 'code': 'invalid_bundle'}
    if m['accountant'] == 'payees':
        for e in r:                            # Model B: recipient identity IS the key
            if e != '*' and KEY_RE.fullmatch(e) is None:
                return {'ok': False, 'code': 'invalid_bundle'}
    if _strict_timestamp(m['notAfter']) is None:
        return {'ok': False, 'code': 'invalid_bundle'}
    return {'ok': True}


def mandate_digest(m):
    """§5: 'sha256:' + lowerhex(SHA-256(tag || JCS(mandate)))"""
    return 'sha256:' + hashlib.sha256(MANDATE_TAG + jcs(m).encode('utf-8')).hexdigest()


def verify_mandate_envelope(env):
    if not isinstance(env, dict) or 'mandate' not in env:
        return {'ok': False, 'code': 'malformed_input'}
    if env.get('alg') != 'Ed25519':            # §4: sole legal alg
        return {'ok': False, 'code': 'invalid_signature'}
    sig = env.get('sig')
    if not isinstance(sig, str) or SIG_RE.fullmatch(sig) is None:
        return {'ok': False, 'code': 'malformed_input'}
    shape = validate_mandate_shape(env['mandate'])
    if not shape['ok']:
        return shape
    m = env['mandate']
    try:
        signable = MANDATE_TAG + jcs(m).encode('utf-8')
    except JcsError:
        return {'ok': False, 'code': 'malformed_input'}
    if not ed25519_verify(signable, _b64url_decode(sig), _b64url_decode(m['issuer'])):
        return {'ok': False, 'code': 'invalid_signature'}
    return {'ok': True, 'digest': mandate_digest(m)}


def compute_binding(mandate_digest_str, payment_id):
    """§7: B = SHA-256(tag || UTF8(mandateDigest || "\\n" || paymentId)).
    mandateDigest keeps its literal 'sha256:' prefix -- 71 chars."""
    if MANDATE_DIGEST_RE.fullmatch(mandate_digest_str) is None:
        raise ValueError('malformed_input')
    if PAYMENT_ID_RE.fullmatch(payment_id) is None:
        raise ValueError('malformed_input')
    pre = (mandate_digest_str + '\n' + payment_id).encode('utf-8')
    return hashlib.sha256(BINDING_TAG + pre).digest()


def compute_all_encodings(mandate_digest_str, payment_id):
    b = compute_binding(mandate_digest_str, payment_id)
    return {
        'eip3009': '0x' + b.hex(),                          # 0x + lowerhex
        'permit2': str(int.from_bytes(b, 'big')),           # decimal uint256
        'xrpl': b.hex().upper(),                            # UPPERCASE hex
    }


def _recipient_in_scope(recipients, recipient):
    if len(recipients) == 1 and recipients[0] == '*':
        return True
    return recipient in recipients


def authorize_payment(env, payment, now_iso):
    """§6, and TOTAL: every path returns a verdict, never raises."""
    try:
        if not isinstance(payment, dict):
            return {'verdict': 'deny', 'code': 'malformed_input'}
        for f in ['payer', 'recipient', 'asset', 'amount', 'mandateDigest']:
            if not isinstance(payment.get(f), str) or payment[f] == '':
                return {'verdict': 'deny', 'code': 'malformed_input'}
        if 'at' in payment and (not isinstance(payment['at'], str)
                                or TIMESTAMP_RE.fullmatch(payment['at']) is None):
            return {'verdict': 'deny', 'code': 'malformed_input'}
        ev = verify_mandate_envelope(env)
        if not ev['ok']:
            return {'verdict': 'deny', 'code': ev['code']}
        m = env['mandate']
        if payment['mandateDigest'] != ev['digest']:
            return {'verdict': 'deny', 'code': 'request_mismatch'}
        if payment['payer'] != m['subject']:
            return {'verdict': 'deny', 'code': 'request_mismatch'}
        if payment['asset'] != m['asset']:
            return {'verdict': 'deny', 'code': 'request_mismatch'}
        if not _recipient_in_scope(m['recipients'], payment['recipient']):
            return {'verdict': 'deny', 'code': 'request_mismatch'}
        if AMOUNT_RE.fullmatch(payment['amount']) is None:
            return {'verdict': 'deny', 'code': 'malformed_input'}
        amt = int(payment['amount'])
        if 'perPayment' in m and amt > int(m['perPayment']):
            return {'verdict': 'deny', 'code': 'scope_exceeded'}
        if amt > int(m['cap']):
            return {'verdict': 'deny', 'code': 'scope_exceeded'}
        now = _strict_timestamp(now_iso)
        if now is None:
            return {'verdict': 'deny', 'code': 'malformed_input'}
        # §6 rule 7: verifier's clock; at-or-after notAfter is unauthorized.
        if now >= _strict_timestamp(m['notAfter']):
            return {'verdict': 'deny', 'code': 'expired'}
        return {'verdict': 'allow', 'code': None}
    except Exception:                                  # noqa: BLE001 -- totality
        return {'verdict': 'deny', 'code': 'malformed_input'}


def verify_post_settlement(env, payment_id, settled, committed_amount=None):
    """§6 'Settled payments' + §13 rule 4 -- every compared field is read from
    the DECODED SETTLED ARTIFACT, never from a presented object."""
    try:
        ev = verify_mandate_envelope(env)
        if not ev['ok']:
            return {'verdict': 'refuted', 'code': ev['code']}
        m = env['mandate']
        if not isinstance(settled, dict):
            return {'verdict': 'refuted', 'code': 'malformed_input'}
        scheme = settled.get('scheme')
        slot = settled.get('slot')
        # Partial binding info fails closed rather than being read as a
        # spec-sanctioned omission of both.
        if (scheme is None) != (slot is None):
            return {'verdict': 'refuted', 'code': 'malformed_input'}
        if scheme is not None:
            enc = compute_all_encodings(ev['digest'], payment_id)
            # The spec's §7 table names schemes in PROSE ("EIP-3009") and never
            # defines the wire token for `scheme`. The only machine-readable
            # evidence is the object key in #3220's own fixture: `eip3009`.
            # An implementer reading the prose alone plausibly emits
            # `eip-3009` -- and a fail-closed verifier then REFUTES a compliant
            # settlement. See PROOF.md defect D-3.
            key = {'eip3009': 'eip3009', 'permit2': 'permit2', 'xrpl': 'xrpl'}.get(scheme)
            if key is None:
                return {'verdict': 'refuted', 'code': 'malformed_input'}
            if enc[key] != slot:
                return {'verdict': 'refuted', 'code': 'invalid_proof'}
        for f in ['payer', 'recipient', 'asset', 'amount']:
            if not isinstance(settled.get(f), str) or settled[f] == '':
                return {'verdict': 'refuted', 'code': 'malformed_input'}
        if AMOUNT_RE.fullmatch(settled['amount']) is None:
            return {'verdict': 'refuted', 'code': 'malformed_input'}
        decoded = int(settled['amount'])
        if committed_amount is not None and str(committed_amount) != settled['amount']:
            return {'verdict': 'refuted', 'code': 'request_mismatch'}
        if settled['payer'] != m['subject']:
            return {'verdict': 'refuted', 'code': 'request_mismatch'}
        if settled['asset'] != m['asset']:
            return {'verdict': 'refuted', 'code': 'request_mismatch'}
        if not _recipient_in_scope(m['recipients'], settled['recipient']):
            return {'verdict': 'refuted', 'code': 'request_mismatch'}
        if 'perPayment' in m and decoded > int(m['perPayment']):
            return {'verdict': 'refuted', 'code': 'scope_exceeded'}
        if decoded > int(m['cap']):
            return {'verdict': 'refuted', 'code': 'scope_exceeded'}
        return {'verdict': 'complied', 'code': None}
    except Exception:                                  # noqa: BLE001 -- totality
        return {'verdict': 'refuted', 'code': 'malformed_input'}


# -----------------------------------------------------------------------------
# Uniform op dispatch -- identical interface to implementation A.
# -----------------------------------------------------------------------------
def _op_jcs(a):
    try:
        c = jcs(a['value'])
        return {'ok': True, 'canonical': c, 'sha256': sha256hex(c)}
    except JcsError as e:
        return {'ok': False, 'error': str(e)}


def _op_notary(a):
    try:
        raw = raw_pub_from_pem(a['pubkey_pem']) if 'pubkey_pem' in a \
            else bytes.fromhex(a['pubkey_hex'])
        r = notary_verify(a['receipt'], raw)
        r['ok'] = True
        return r
    except Exception as e:                              # noqa: BLE001
        return {'ok': False, 'error': str(e)}


def _safe(fn, on_err):
    def wrapped(a):
        try:
            return fn(a)
        except Exception as e:                          # noqa: BLE001
            return dict(on_err, error=str(e))
    return wrapped


OPS = {
    'jcs': _op_jcs,
    'notary_receipt': _op_notary,
    'digest_triple': lambda a: digest_triple(a['triple']),
    'digest_limbs': _safe(lambda a: dict(digest_limbs(a['hex']), ok=True), {'ok': False}),
    'limbs_to_hex': _safe(lambda a: {'ok': True, 'hex': limbs_to_hex(a['digest_lo'], a['digest_hi'])}, {'ok': False}),
    'origin_tag': lambda a: origin_tag_felt(a['origin_tag']),
    'v3_batch': lambda a: v3_batch_check(a['K'], a['leaves']),
    'base_settlement_v1': _safe(lambda a: base_settlement_v1(a['fields']), {'valid': False}),
    'mandate_shape': lambda a: (lambda r: {'ok': r['ok'], 'code': None if r['ok'] else r['code']})(validate_mandate_shape(a['mandate'])),
    'mandate_digest': _safe(
        lambda a: ({'ok': True, 'digest': mandate_digest(a['mandate'])}
                   if validate_mandate_shape(a['mandate'])['ok']
                   else {'ok': False, 'code': validate_mandate_shape(a['mandate'])['code']}),
        {'ok': False, 'code': 'malformed_input'}),
    'binding': _safe(lambda a: dict(compute_all_encodings(a['mandateDigest'], a['paymentId']), ok=True), {'ok': False}),
    'authorize': lambda a: authorize_payment(a['envelope'], a['payment'], a['now_iso']),
    'settle_compare': lambda a: verify_post_settlement(
        a['envelope'], a['paymentId'], a['settled'], a.get('committedAmount')),
}


def run_ops(ops):
    out = []
    for o in ops:
        fn = OPS.get(o['op'])
        if fn is None:
            out.append({'id': o.get('id'), 'error': 'unknown_op_' + o['op']})
            continue
        try:
            res = fn(o.get('args') or {})
        except Exception as e:                          # noqa: BLE001
            res = {'fatal': str(e)}
        out.append({'id': o.get('id'), 'op': o['op'], 'result': res})
    return out


if __name__ == '__main__':
    src = sys.stdin.read() if len(sys.argv) < 2 or sys.argv[1] == '-' \
        else open(sys.argv[1], encoding='utf-8').read()
    data = json.loads(src)
    ops = data if isinstance(data, list) else data.get('ops', [data])
    sys.stdout.write(json.dumps({'impl': 'python', 'results': run_ops(ops)}) + '\n')
