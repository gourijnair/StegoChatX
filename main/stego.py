# stego.py
import io
import math
import random
import struct
from typing import Tuple

from PIL import Image

# LSB-based steganography with pseudo-random pixel ordering.
# We embed raw bytes into least-significant bits of RGB channels.
# Payload is preceded by a 32-bit length header (big-endian), so extraction knows how many bytes to read.

def _bytes_to_bits(data: bytes) -> str:
    return ''.join(f"{b:08b}" for b in data)

def _bits_to_bytes(bits: str) -> bytes:
    b = bytearray()
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8:
            byte = byte.ljust(8, '0')
        b.append(int(byte, 2))
    return bytes(b)

def embed_bytes_into_png(cover_image_bytes: bytes, payload: bytes, seed: int = None) -> bytes:
    """
    cover_image_bytes: bytes of a PNG image
    payload: bytes to embed
    seed: optional integer seed for pseudo-random pixel order (should be stored in metadata)
    Returns PNG bytes of stego image.
    """
    img = Image.open(io.BytesIO(cover_image_bytes)).convert("RGB")
    w, h = img.size
    pixels = img.load()

    # prepare bits: 4-byte big-endian length + payload
    length_prefix = struct.pack(">I", len(payload))
    full = length_prefix + payload
    bits = _bytes_to_bits(full)
    capacity = w * h * 3  # 3 LSBs per pixel
    if len(bits) > capacity:
        raise ValueError(f"Payload too large for cover image capacity ({len(bits)} bits > {capacity})")

    # generate pseudo-random positions
    total_slots = w * h * 3
    indices = list(range(total_slots))
    rng = random.Random(seed)
    rng.shuffle(indices)

    # embed
    bit_idx = 0
    for slot in indices:
        if bit_idx >= len(bits):
            break
        pixel_index = slot // 3
        channel = slot % 3  # 0:R,1:G,2:B
        x = pixel_index % w
        y = pixel_index // w
        r, g, b = pixels[x, y]
        channels = [r, g, b]
        bit = int(bits[bit_idx])
        channels[channel] = (channels[channel] & ~1) | bit
        pixels[x, y] = tuple(channels)
        bit_idx += 1

    # save to bytes
    out = io.BytesIO()
    img.save(out, format="PNG")
    return out.getvalue()

def extract_bytes_from_png(stego_png_bytes: bytes, seed: int = None) -> bytes:
    img = Image.open(io.BytesIO(stego_png_bytes)).convert("RGB")
    w, h = img.size
    pixels = img.load()

    total_slots = w * h * 3
    indices = list(range(total_slots))
    rng = random.Random(seed)
    rng.shuffle(indices)

    # Extract enough bits to read 4-byte length header first
    bits = []
    # Read first 32 bits (length header)
    for i in range(32):
        slot = indices[i]
        pixel_index = slot // 3
        channel = slot % 3
        x = pixel_index % w
        y = pixel_index // w
        r, g, b = pixels[x, y]
        channels = [r, g, b]
        bits.append(str(channels[channel] & 1))
    length_bytes = _bits_to_bytes(''.join(bits))
    payload_len = struct.unpack(">I", length_bytes)[0]

    # Now we know how many bits the payload needs: payload_len * 8
    needed_bits = (payload_len + 4) * 8  # includes the 4-byte header
    if needed_bits > total_slots:
        raise ValueError("Stego image does not contain enough data")

    # Extract the full bitstream (we already have first 32 bits)
    bits = []
    for i in range(needed_bits):
        slot = indices[i]
        pixel_index = slot // 3
        channel = slot % 3
        x = pixel_index % w
        y = pixel_index // w
        r, g, b = pixels[x, y]
        channels = [r, g, b]
        bits.append(str(channels[channel] & 1))

    data = _bits_to_bytes(''.join(bits))
    # Strip the 4-byte length prefix
    return data[4:]
