"""Xbox face-button labels in the game's button font (scripts/make_romfs_patches.py --glyphs xbox).

The prompts' button icons are glyphs of Font/Font.Nin_NX_NVN.bfarc's scft/External.bfotf: an OpenType (CFF) font
behind Nintendo's BFOTF wrapper (an 8-byte header, every 32-bit big-endian word XORed with a per-file key). U+E040 is
the Switch's A (the right face button), U+E041 B (bottom), U+E042 X (top), U+E043 Y (left). With an Xbox controller
mapped by position (runtime/gamepad_layout.h), the right button is labelled B, the bottom A, the top Y and the left X, so
the outlines of A and B and of X and Y trade places: the game's own artwork, each letter where the Xbox controller has
it. The CharStrings INDEX keeps its size, so the font, the archive member and the archive keep theirs and are edited in
place. Advance widths of each swapped pair must be equal (checked).

LB / RB / LT / RT and the menu / view buttons replace L / R / ZL / ZR and + / - with Kenney's CC0 Xbox shapes
(XBOX_SHAPES, assets/xbox-prompts); that font grows, so its archive is rebuilt (sarc_replace).
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

# Shoulder buttons, triggers and the two small buttons get the Xbox shapes from Kenney's Input Prompts (CC0, assets/
# xbox-prompts): each SVG is one path whose letters are holes, which is what a one-colour glyph needs. It is fitted into
# the bounding box of the glyph it replaces, keeping its proportions.
XBOX_SHAPES = {0xE044: 'xbox_lb', 0xE045: 'xbox_rb', 0xE046: 'xbox_lt', 0xE047: 'xbox_rt',
               0xE04B: 'xbox_button_menu', 0xE04C: 'xbox_button_view'}

def replace_shapes(otf, svg_dir):
    """The OpenType bytes with XBOX_SHAPES drawn from svg_dir (needs fontTools; the font grows)."""
    import io
    from fontTools.ttLib import TTFont
    from fontTools.pens.boundsPen import BoundsPen
    from fontTools.pens.t2CharStringPen import T2CharStringPen
    from fontTools.svgLib.path import SVGPath
    font = TTFont(io.BytesIO(bytes(otf)))
    cff = font['CFF '].cff; top = cff.topDictIndex[0]; strings = top.CharStrings; glyphs = font.getGlyphSet()
    private = top.Private; cmap = font.getBestCmap()
    for cp, name in XBOX_SHAPES.items():
        glyph = cmap[cp]
        old = BoundsPen(glyphs); glyphs[glyph].draw(old); x0, y0, x1, y1 = old.bounds
        svg = SVGPath(filename=str(svg_dir / f'{name}.svg'))
        src = BoundsPen(None); svg.draw(src); sx0, sy0, sx1, sy1 = src.bounds
        k = min((x1 - x0) / (sx1 - sx0), (y1 - y0) / (sy1 - sy0))
        tx = (x0 + x1) / 2 - k * (sx0 + sx1) / 2; ty = (y0 + y1) / 2 + k * (sy0 + sy1) / 2   # the SVG's y grows downwards
        advance = font['hmtx'][glyph][0]
        width = None if advance == getattr(private, 'defaultWidthX', 0) else advance - getattr(private, 'nominalWidthX', 0)
        pen = T2CharStringPen(width, None)
        SVGPath(filename=str(svg_dir / f'{name}.svg'), transform=(k, 0, 0, -k, tx, ty)).draw(pen)
        strings[glyph] = pen.getCharString(private=private, globalSubrs=cff.GlobalSubrs)
    out = io.BytesIO(); font.save(out)
    return bytearray(out.getvalue())

def apply_xbox(member, svg_dir=None):
    """The BFOTF bytes with the Xbox labels: the face buttons always (same length), the shoulder / trigger / menu / view
    shapes too when svg_dir is given (the font then grows: see sarc_replace)."""
    otf, key = bfotf_decode(member)
    otf = swap_outlines(otf, XBOX_SWAPS)
    if svg_dir is None:
        out = bfotf_encode(otf, key, len(member)); assert len(out) == len(member); return out
    otf = replace_shapes(otf, svg_dir)
    return bfotf_encode(otf, key, 8 + (len(otf) + 3) // 4 * 4)

def sarc_replace(arc, name, data):
    """The SARC with one member replaced by data of any length. Members stored after it move by a multiple of 0x2000, so
    each keeps its alignment."""
    arc = bytearray(arc)
    assert arc[:4] == b'SARC' and arc[6:8] == b'\xff\xfe'
    header, size, start = struct.unpack_from('<HxxII', arc, 4)
    count = struct.unpack_from('<H', arc, header + 6)[0]; names = header + 12 + count * 16 + 8
    nodes = []
    for i in range(count):
        e = header + 12 + i * 16; attr, lo, hi = struct.unpack_from('<3I', arc, e + 4)
        o = names + (attr & 0xffffff) * 4; nodes.append((arc[o:arc.index(0, o, start)].decode(), e, lo, hi))
    _, entry, lo, hi = next(n for n in nodes if n[0] == name)
    following = [n for n in nodes if n[2] >= hi]
    room = (min(n[2] for n in following) if following else len(arc) - start) - lo
    shift = 0 if len(data) <= room else -(-(len(data) - room) // 0x2000) * 0x2000
    tail = bytes(arc[start + min(n[2] for n in following):]) if following else b''
    body = bytes(arc[:start + lo]) + bytes(data) + b'\0' * (room + shift - len(data)) + tail
    out = bytearray(body)
    struct.pack_into('<I', out, entry + 12, lo + len(data))
    for _, e, flo, fhi in following: struct.pack_into('<II', out, e + 8, flo + shift, fhi + shift)
    struct.pack_into('<I', out, 8, len(out))
    return out

# The HUD's own key icons (equipment and ability hints) are textures of Common.Product's timg/__Combined.bntx, R8 masks
# of 108 x 108 in the Tegra block-linear layout: a white shape, the letter cut out. A / B and X / Y trade places like the
# font's; L and ZL are redrawn from Kenney's LB and LT, fitted into the box the original shape covers.
HUD_SWAPS = (('Nt_KeyTexA_00^d', 'Nt_KeyTexB_00^d'), ('Nt_KeyTexX_00^d', 'Nt_KeyTexY_00^d'))
HUD_SHAPES = {'Nt_KeyTexL_00^d': 'xbox_lb', 'Nt_KeyTexZL_00^d': 'xbox_lt'}
R8_UNORM = 0x201

def bntx_textures(b):
    """name -> (format, width, height, block height log2, data offset, size) of every texture in a BNTX."""
    assert b[:4] == b'BNTX' and b[0x20:0x24] == b'NX  '
    count, infos = struct.unpack_from('<IQ', b, 0x24)
    out = {}
    for i in range(count):
        ti = struct.unpack_from('<Q', b, infos + 8 * i)[0]; assert b[ti:ti + 4] == b'BRTI'
        fmt, _, w, h, _, _, bh = struct.unpack_from('<7I', b, ti + 0x1c)
        size = struct.unpack_from('<I', b, ti + 0x50)[0]
        name_ptr, _, mip_ptr = struct.unpack_from('<QQQ', b, ti + 0x60)
        name = bytes(b[name_ptr + 2:name_ptr + 2 + struct.unpack_from('<H', b, name_ptr)[0]]).decode()
        out[name] = (fmt, w, h, bh, struct.unpack_from('<Q', b, mip_ptr)[0], size)
    return out

def gob_offset(x, y, width_bytes, block_height):
    """Byte offset of (x bytes, y rows) in a Tegra X1 block-linear surface (GOB: 64 bytes x 8 rows, 512 bytes)."""
    block = (y // (8 * block_height)) * ((width_bytes + 63) // 64) + x // 64
    xo, yo = x % 64, y % 8
    return (block * block_height + (y % (8 * block_height)) // 8) * 512 + (xo // 32) * 256 + (yo // 2) * 64 + ((xo % 32) // 16) * 32 + (yo % 2) * 16 + xo % 16

def rasterize(svg_file, box, w, h, samples=4):
    """An R8 mask (bytes, w x h) of the SVG path fitted into box (x0, y0, x1, y1), keeping its proportions; nonzero fill,
    samples x samples supersampling per pixel."""
    from fontTools.pens.recordingPen import RecordingPen
    from fontTools.pens.boundsPen import BoundsPen
    from fontTools.svgLib.path import SVGPath
    rec = RecordingPen(); SVGPath(filename=str(svg_file)).draw(rec)
    bounds = BoundsPen(None); rec.replay(bounds); sx0, sy0, sx1, sy1 = bounds.bounds
    x0, y0, x1, y1 = box; k = min((x1 - x0) / (sx1 - sx0), (y1 - y0) / (sy1 - sy0))
    ox, oy = (x0 + x1) / 2 - k * (sx0 + sx1) / 2, (y0 + y1) / 2 - k * (sy0 + sy1) / 2
    edges, cur, start = [], None, None
    def pt(p): return (ox + k * p[0], oy + k * p[1])
    def line(a, b):
        if a[1] != b[1]: edges.append((a, b))
    for op, args in rec.value:
        if op == 'moveTo': cur = start = pt(args[0])
        elif op == 'lineTo': nxt = pt(args[0]); line(cur, nxt); cur = nxt
        elif op == 'qCurveTo':
            pts = [cur] + [pt(a) for a in args]
            for i in range(1, len(pts) - 1):   # implied on-curve points between consecutive off-curve ones
                p0 = pts[0] if i == 1 else ((pts[i - 1][0] + pts[i][0]) / 2, (pts[i - 1][1] + pts[i][1]) / 2)
                p2 = pts[i + 1] if i == len(pts) - 2 else ((pts[i][0] + pts[i + 1][0]) / 2, (pts[i][1] + pts[i + 1][1]) / 2)
                prev = p0
                for s in range(1, 9):
                    t = s / 8; q = ((1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * pts[i][0] + t * t * p2[0], (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * pts[i][1] + t * t * p2[1])
                    line(prev, q); prev = q
            cur = pts[-1]
        elif op == 'curveTo':
            p0, (p1, p2, p3) = cur, [pt(a) for a in args]; prev = p0
            for s in range(1, 13):
                t = s / 12; u = 1 - t
                q = tuple(u ** 3 * p0[j] + 3 * u * u * t * p1[j] + 3 * u * t * t * p2[j] + t ** 3 * p3[j] for j in (0, 1))
                line(prev, q); prev = q
            cur = p3
        elif op in ('closePath', 'endPath'):
            if cur and start: line(cur, start)
            cur = start
    out = bytearray(w * h)
    for y in range(h):
        row = [0] * w
        for sy in range(samples):
            yy = y + (sy + 0.5) / samples
            xs = []
            for (ax, ay), (bx, by) in edges:
                if (ay <= yy < by) or (by <= yy < ay):
                    xs.append((ax + (yy - ay) * (bx - ax) / (by - ay), 1 if by > ay else -1))
            xs.sort()
            for sx in range(samples):
                for x in range(w):
                    xx = x + (sx + 0.5) / samples; wind = 0
                    for ex, d in xs:
                        if ex > xx: break
                        wind += d
                    if wind: row[x] += 1
        for x in range(w): out[y * w + x] = min(255, row[x] * 255 // (samples * samples))
    return bytes(out)

def apply_hud(blarc, members, svg_dir):
    """Edits Common.Product's texture atlas in place (same sizes). Returns the member it changed."""
    lo, hi = members['timg/__Combined.bntx']; b = memoryview(blarc)[lo:hi]
    tex = bntx_textures(b)
    for a, c in HUD_SWAPS:
        ta, tc = tex[a], tex[c]; assert ta[:4] == tc[:4] and ta[5] == tc[5] and ta[0] == R8_UNORM, (a, c)
        da, dc = bytes(b[ta[4]:ta[4] + ta[5]]), bytes(b[tc[4]:tc[4] + tc[5]])
        b[ta[4]:ta[4] + ta[5]] = dc; b[tc[4]:tc[4] + tc[5]] = da
    for name, svg in HUD_SHAPES.items():
        fmt, w, h, bh, off, size = tex[name]; assert fmt == R8_UNORM, name
        src = bytes(b[off:off + size]); lin = [src[gob_offset(x, y, w, 1 << bh)] for y in range(h) for x in range(w)]
        xs = [i % w for i, v in enumerate(lin) if v > 128]; ys = [i // w for i, v in enumerate(lin) if v > 128]
        mask = rasterize(svg_dir / f'{svg}.svg', (min(xs), min(ys), max(xs) + 1, max(ys) + 1), w, h)
        for y in range(h):
            for x in range(w): b[off + gob_offset(x, y, w, 1 << bh)] = mask[y * w + x]
    return 'timg/__Combined.bntx'
