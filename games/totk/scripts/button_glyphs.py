"""Xbox face-button labels in the game's button font (scripts/make_romfs_patches.py --glyphs xbox).

The prompts' button icons are glyphs of Font/Font.Nin_NX_NVN.bfarc's scft/External.bfotf: an OpenType (CFF) font
behind Nintendo's BFOTF wrapper (an 8-byte header, every 32-bit big-endian word XORed with a per-file key). U+E040 is
the Switch's A (the right face button), U+E041 B (bottom), U+E042 X (top), U+E043 Y (left). With an Xbox controller
mapped by position (runtime/gamepad_layout.h), the right button is labelled B, the bottom A, the top Y and the left X, so
the outlines of A and B and of X and Y trade places: the game's own artwork, each letter where the Xbox controller has
it. The CharStrings INDEX keeps its size, so the font, the archive member and the archive keep theirs and are edited in
place. Advance widths of each swapped pair must be equal (checked).
"""
import struct

BFOTF_MAGIC = 0x7f9a0218   # the first word once the key is removed
XBOX_SWAPS = ((0xE040, 0xE041), (0xE042, 0xE043))

def bfotf_key(data):
    return struct.unpack_from('>I', data, 0)[0] ^ BFOTF_MAGIC

def bfotf_decode(data):
    key = bfotf_key(data)
    size = struct.unpack_from('>I', data, 4)[0] ^ key
    words = struct.unpack_from(f'>{(len(data) - 8) // 4}I', data, 8)
    return bytearray(struct.pack(f'>{len(words)}I', *(w ^ key for w in words)))[:size], key

def bfotf_encode(otf, key, length):
    pad = bytes(otf) + b'\0' * (length - 8 - len(otf))
    words = struct.unpack(f'>{len(pad) // 4}I', pad)
    return struct.pack('>II', BFOTF_MAGIC ^ key, len(otf) ^ key) + struct.pack(f'>{len(words)}I', *(w ^ key for w in words))

def tables(otf):
    count = struct.unpack_from('>H', otf, 4)[0]
    return {bytes(otf[12 + 16 * i:16 + 16 * i]).decode(): struct.unpack_from('>II', otf, 20 + 16 * i) for i in range(count)}

def cmap_glyph(otf, cmap_off, cp):
    """Glyph ID of a BMP code point through the first (3, 1) or (0, 3) format 4 subtable."""
    n = struct.unpack_from('>H', otf, cmap_off + 2)[0]
    for i in range(n):
        plat, enc, off = struct.unpack_from('>HHI', otf, cmap_off + 4 + 8 * i)
        sub = cmap_off + off
        if (plat, enc) in ((3, 1), (0, 3)) and struct.unpack_from('>H', otf, sub)[0] == 4:
            segs = struct.unpack_from('>H', otf, sub + 6)[0] // 2
            ends, starts = sub + 14, sub + 16 + 2 * segs
            deltas, ranges = starts + 2 * segs, starts + 4 * segs
            for s in range(segs):
                end, start = struct.unpack_from('>H', otf, ends + 2 * s)[0], struct.unpack_from('>H', otf, starts + 2 * s)[0]
                if start <= cp <= end:
                    delta, roff = struct.unpack_from('>hH', otf, deltas + 2 * s)[0], struct.unpack_from('>H', otf, ranges + 2 * s)[0]
                    if roff == 0: return (cp + delta) & 0xffff
                    gid = struct.unpack_from('>H', otf, ranges + 2 * s + roff + 2 * (cp - start))[0]
                    return (gid + delta) & 0xffff if gid else 0
    raise KeyError(hex(cp))

def cff_charstrings(otf, cff_off):
    """(offsets table position, offSize, data start) of the CharStrings INDEX."""
    def index_end(pos):
        count = struct.unpack_from('>H', otf, pos)[0]
        if count == 0: return pos + 2
        size = otf[pos + 2]; last = int.from_bytes(otf[pos + 3 + size * count:pos + 3 + size * (count + 1)], 'big')
        return pos + 3 + size * (count + 1) + last - 1
    pos = cff_off + otf[cff_off + 2]          # header size
    pos = index_end(pos)                       # Name INDEX
    count, size = struct.unpack_from('>H', otf, pos)[0], otf[pos + 2]   # Top DICT INDEX (one dict)
    o0 = int.from_bytes(otf[pos + 3:pos + 3 + size], 'big'); o1 = int.from_bytes(otf[pos + 3 + size:pos + 3 + 2 * size], 'big')
    data = pos + 3 + size * (count + 1) - 1
    d, end, stack, charstrings = data + o0, data + o1, [], None
    while d < end:                             # the Top DICT: operands then an operator; CharStrings is operator 17
        b = otf[d]
        if b == 28: stack.append(struct.unpack_from('>h', otf, d + 1)[0]); d += 3
        elif b == 29: stack.append(struct.unpack_from('>i', otf, d + 1)[0]); d += 5
        elif b == 30:
            d += 1
            while not ((otf[d] & 0xf) == 0xf or (otf[d] >> 4) == 0xf): d += 1
            d += 1; stack.append(0.0)
        elif 32 <= b <= 246: stack.append(b - 139); d += 1
        elif 247 <= b <= 250: stack.append((b - 247) * 256 + otf[d + 1] + 108); d += 2
        elif 251 <= b <= 254: stack.append(-(b - 251) * 256 - otf[d + 1] - 108); d += 2
        else:
            op = (1200 + otf[d + 1]) if b == 12 else b; d += 2 if b == 12 else 1
            if op == 17: charstrings = cff_off + stack[-1]
            stack = []
    assert charstrings, 'no CharStrings in the Top DICT'
    count, size = struct.unpack_from('>H', otf, charstrings)[0], otf[charstrings + 2]
    return charstrings + 3, size, charstrings + 3 + size * (count + 1) - 1

def swap_outlines(otf, swaps):
    t = tables(otf)
    cff_off = t['CFF '][0]; hmtx_off = t['hmtx'][0]; nmetrics = struct.unpack_from('>H', otf, t['hhea'][0] + 34)[0]
    offsets, size, data = cff_charstrings(otf, cff_off)
    def rng(g):
        a = int.from_bytes(otf[offsets + size * g:offsets + size * (g + 1)], 'big')
        b = int.from_bytes(otf[offsets + size * (g + 1):offsets + size * (g + 2)], 'big')
        return a, b
    def advance(g): return struct.unpack_from('>H', otf, hmtx_off + 4 * min(g, nmetrics - 1))[0]
    for cp_a, cp_b in swaps:
        ga, gb = sorted((cmap_glyph(otf, t['cmap'][0], cp_a), cmap_glyph(otf, t['cmap'][0], cp_b)))
        assert advance(ga) == advance(gb), (hex(cp_a), hex(cp_b), advance(ga), advance(gb))
        (a0, a1), (b0, b1) = rng(ga), rng(gb)
        assert a1 <= b0, 'glyph order'
        sa, sb, mid = bytes(otf[data + a0:data + a1]), bytes(otf[data + b0:data + b1]), bytes(otf[data + a1:data + b0])
        otf[data + a0:data + b1] = sb + mid + sa   # same total length
        for g in range(ga + 1, gb + 1):            # the offsets of ga+1 .. gb move by the size difference
            o = int.from_bytes(otf[offsets + size * g:offsets + size * (g + 1)], 'big') + len(sb) - len(sa)
            otf[offsets + size * g:offsets + size * (g + 1)] = o.to_bytes(size, 'big')
    return otf

def apply_xbox(member):
    """The BFOTF bytes with the Xbox labels; same length as given."""
    otf, key = bfotf_decode(member)
    out = bfotf_encode(swap_outlines(otf, XBOX_SWAPS), key, len(member))
    assert len(out) == len(member)
    return out
