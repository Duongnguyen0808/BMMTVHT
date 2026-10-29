import io
from datetime import datetime, timezone
from PIL import Image, ImageDraw, ImageFont


def apply_watermark_to_image(image_bytes: bytes, watermark_text: str) -> bytes:
    """
    Apply a forensic dynamic semi-transparent diagonal watermark across an image
    using Pillow (PIL) for Data Loss Prevention (DLP) and forensic traceability.
    """
    try:
        base_image = Image.open(io.BytesIO(image_bytes)).convert("RGBA")
        width, height = base_image.size

        # Create transparent overlay
        overlay = Image.new("RGBA", (width, height), (255, 255, 255, 0))
        draw = ImageDraw.Draw(overlay)

        # Estimate font size based on image dimensions
        font_size = max(18, int(width / 35))
        try:
            # Try system font if available, otherwise load default
            font = ImageFont.truetype("arial.ttf", font_size)
        except Exception:
            font = ImageFont.load_default()

        # Watermark text properties: High-contrast semi-transparent red/gray
        # RGBA: Red with ~30% opacity (R=220, G=38, B=38, A=85)
        text_color = (220, 38, 38, 85)

        # Draw diagonal repeats across the image
        step_x = max(250, int(width / 3))
        step_y = max(150, int(height / 4))

        for y in range(0, height + 100, step_y):
            for x in range(-100, width + 100, step_x):
                # We can draw angled text using Pillow rotate or staggered text
                draw.text((x, y), watermark_text, fill=text_color, font=font)

        # Rotate overlay slightly for diagonal watermark look
        rotated_overlay = overlay.rotate(25, resample=Image.Resampling.BICUBIC, center=(width / 2, height / 2))

        # Composite the overlay onto base image
        watermarked = Image.alpha_composite(base_image, rotated_overlay)

        output = io.BytesIO()
        watermarked.convert("RGB").save(output, format="JPEG", quality=90)
        return output.getvalue()
    except Exception as e:
        # Graceful fallback: return original bytes if image decoding fails
        return image_bytes


def apply_watermark_to_text(text_bytes: bytes, watermark_text: str) -> bytes:
    """
    Embed forensic audit tracking metadata into plaintext files for DLP tracking.
    """
    try:
        content = text_bytes.decode('utf-8', errors='replace')
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        header = (
            "================================================================================\n"
            f"[!] SECURESHARE FORENSIC DLP WATERMARK - NGIÊM CẤM SAO CHÉP / PHÁT TÁN\n"
            f"[!] Người tải về: {watermark_text}\n"
            f"[!] Thời gian tải: {now_utc}\n"
            "[!] Dữ liệu được định danh pháp lý phục vụ truy vết rò rỉ thông tin số (DLP).\n"
            "================================================================================\n\n"
        )
        footer = (
            "\n\n================================================================================\n"
            f"[!] KẾT THÚC VĂN BẢN MẬT — ĐƯỢC BẢO VỆ BỞI SECURESHARE DLP ENGINE\n"
            "================================================================================\n"
        )
        return (header + content + footer).encode('utf-8')
    except Exception:
        return text_bytes


def apply_forensic_watermark(raw_bytes: bytes, filename: str, user_display: str, ip_address: str) -> bytes:
    """
    Dynamically route watermarking based on file extension.
    """
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    watermark_label = f"CONFIDENTIAL - {user_display} - IP: {ip_address}"

    if ext in ['png', 'jpg', 'jpeg']:
        return apply_watermark_to_image(raw_bytes, watermark_label)
    elif ext in ['txt', 'log', 'csv']:
        return apply_watermark_to_text(raw_bytes, f"{user_display} (IP: {ip_address})")
    
    return raw_bytes
