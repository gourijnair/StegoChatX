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
    print("    🖼️  STEGANOGRAPHY - EMBEDDING PROCESS")
    print("    " + "=" * 45)
    
    print("    [3.1] Loading and analyzing cover image...")
    img = Image.open(io.BytesIO(cover_image_bytes)).convert("RGB")
    w, h = img.size
    pixels = img.load()
    print(f"        • Image dimensions: {w} x {h} pixels")
    print(f"        • Total pixels: {w * h:,}")
    print(f"        • Color channels: RGB (3 channels per pixel)")

    # prepare bits: 4-byte big-endian length + payload
    print("\n    [3.2] Preparing payload for embedding...")
    length_prefix = struct.pack(">I", len(payload))
    full = length_prefix + payload
    bits = _bytes_to_bits(full)
    capacity = w * h * 3  # 3 LSBs per pixel
    print(f"        • Payload size: {len(payload)} bytes")
    print(f"        • Length prefix: {len(length_prefix)} bytes")
    print(f"        • Total data to embed: {len(full)} bytes")
    print(f"        • Data as bits: {len(bits)} bits")
    print(f"        • Available capacity: {capacity:,} bits")
    
    if len(bits) > capacity:
        raise ValueError(f"❌ Payload too large for cover image capacity ({len(bits)} bits > {capacity})")
    
    utilization = (len(bits) / capacity) * 100
    print(f"        • Capacity utilization: {utilization:.2f}%")
    print("        ✓ Payload fits within image capacity")

    # generate pseudo-random positions
    print("\n    [3.3] Generating pseudo-random pixel positions...")
    total_slots = w * h * 3
    indices = list(range(total_slots))
    rng = random.Random(seed)
    rng.shuffle(indices)
    print(f"        • Total available slots: {total_slots:,}")
    print(f"        • Random seed: {seed}")
    print(f"        • Positions shuffled for security")
    print("        ✓ Random embedding positions generated")

    # embed
    print("\n    [3.4] Embedding data using LSB steganography...")
    bit_idx = 0
    modified_pixels = 0
    
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
        old_value = channels[channel]
        channels[channel] = (channels[channel] & ~1) | bit
        if old_value != channels[channel]:
            modified_pixels += 1
        pixels[x, y] = tuple(channels)
        bit_idx += 1

    print(f"        • Bits embedded: {bit_idx}")
    print(f"        • Pixels modified: {modified_pixels:,}")
    print(f"        • Embedding efficiency: {(bit_idx/len(bits))*100:.2f}%")
    print("        ✓ Data embedded successfully using LSB technique")

    # save to bytes
    print("\n    [3.5] Saving stego image...")
    out = io.BytesIO()
    img.save(out, format="PNG")
    stego_bytes = out.getvalue()
    print(f"        • Stego image size: {len(stego_bytes)} bytes")
    print(f"        • Size difference: {len(stego_bytes) - len(cover_image_bytes)} bytes")
    print("        ✓ Stego image saved successfully")

    # display the image
    print("\n    [3.6] Displaying stego image...")
    stego_img = Image.open(io.BytesIO(stego_bytes))
    stego_img.show()  # This opens the image in the default viewer
    print("        ✓ Stego image displayed")
    
    print("    ✓ Message embedded successfully in the image using LSB steganography")
    return stego_bytes

def extract_bytes_from_png(stego_png_bytes: bytes, seed: int = None) -> bytes:
    print("    🔍 STEGANOGRAPHY - EXTRACTION PROCESS")
    print("    " + "=" * 45)
    
    print("    [4.1] Loading stego image...")
    img = Image.open(io.BytesIO(stego_png_bytes)).convert("RGB")
    w, h = img.size
    pixels = img.load()
    print(f"        • Image dimensions: {w} x {h} pixels")
    print(f"        • Total pixels: {w * h:,}")
    print(f"        • Color channels: RGB (3 channels per pixel)")

    print("\n    [4.2] Generating pseudo-random pixel positions...")
    total_slots = w * h * 3
    indices = list(range(total_slots))
    rng = random.Random(seed)
    rng.shuffle(indices)
    print(f"        • Total available slots: {total_slots:,}")
    print(f"        • Random seed: {seed}")
    print(f"        • Positions shuffled for extraction")
    print("        ✓ Random extraction positions generated")

    # Extract enough bits to read 4-byte length header first
    print("\n    [4.3] Extracting length header...")
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
    print(f"        • Length header bits: {''.join(bits)}")
    print(f"        • Length header bytes: {length_bytes.hex()}")
    print(f"        • Payload length: {payload_len} bytes")
    print("        ✓ Length header extracted successfully")

    # Now we know how many bits the payload needs: payload_len * 8
    needed_bits = (payload_len + 4) * 8  # includes the 4-byte header
    print(f"\n    [4.4] Calculating total bits needed...")
    print(f"        • Payload bits needed: {payload_len * 8}")
    print(f"        • Header bits: 32")
    print(f"        • Total bits needed: {needed_bits}")
    print(f"        • Available slots: {total_slots:,}")
    
    if needed_bits > total_slots:
        raise ValueError("❌ Stego image does not contain enough data")
    print("        ✓ Sufficient data available for extraction")

    # Extract the full bitstream (we already have first 32 bits)
    print("\n    [4.5] Extracting complete data...")
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
    print(f"        • Total bits extracted: {len(bits)}")
    print(f"        • Data size: {len(data)} bytes")
    print(f"        • Data preview: {data[:20].hex()}{'...' if len(data) > 20 else ''}")
    print("        ✓ Complete data extracted successfully")

    # Strip the 4-byte length prefix
    payload = data[4:]
    print(f"\n    [4.6] Finalizing extraction...")
    print(f"        • Payload size: {len(payload)} bytes")
    print(f"        • Payload preview: {payload[:20].hex()}{'...' if len(payload) > 20 else ''}")
    print("    ✓ Bytes successfully extracted from PNG using LSB steganography")
    return payload
    
