#!/usr/bin/env python3
"""Render the dispute demo into a subtitled MP4 + teaser GIF from the real demo output.

Requires: pip install imageio imageio-ffmpeg pillow
Run: PYTHONPATH=src .venv/bin/python demo/render_video.py
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile

from PIL import Image, ImageDraw, ImageFont
import imageio.v2 as imageio
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
W, H = 1280, 720
FPS = 10

NARRATION = {
    1: "两个 Agent、一个共享账本：谁签了什么，都留下记录。",
    2: "客户发送请求；版本与附件摘要进入签名账本。",
    3: "执行方交付 v1；这一版被固定下来。",
    4: "客户拒收 v1；理由绑定到这一版，而不是口头拒绝。",
    5: "修订 v2；上一版关系写进记录。",
    6: "只验收 v2；验收 v1 不会自动变成验收 v2。",
    7: "导出证据包：账本、信封、验收、密钥历史。",
    8: "接收方离线核验：五轴通过，内容轴未执行。",
    9: "改一个字节，完整性立刻失败。",
    10: "它证明版本与记录，不证明内容质量与最新历史。",
}

BG = (13, 17, 23)
PANEL = (22, 27, 34)
BORDER = (48, 54, 61)
TEXT = (230, 237, 243)
MUTED = (139, 148, 158)
GREEN = (63, 185, 80)
RED = (248, 81, 73)
AMBER = (210, 153, 34)
ACCENT = (88, 166, 255)

FONT_MONO = "/System/Library/Fonts/Menlo.ttc"
FONT_CJK = "/System/Library/Fonts/Supplemental/Arial Unicode.ttf"


def font(path, size):
    return ImageFont.truetype(path, size)


def capture_demo() -> list[tuple[str, list[str]]]:
    env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"))
    proc = subprocess.run([sys.executable, os.path.join(ROOT, "demo", "run_demo.py")],
                          cwd=ROOT, env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit(proc.stderr)
    text = proc.stdout.replace("\\n", "\n")
    # shorten temp paths in output
    text = re.sub(r"/var/folders/[^\s]+?/T/agentbridge-demo\.[^/\s]+", "./demo-work", text)
    scenes = []
    current_title = None
    current_lines: list[str] = []
    for raw in text.splitlines():
        m = re.match(r"^\[(\d+)\] (.*)$", raw)
        if m:
            if current_title is not None:
                scenes.append((current_title, current_lines))
            current_title = m.group(2)
            current_lines = []
        elif raw.startswith("---"):
            continue
        elif raw.strip():
            current_lines.append(raw)
    if current_title is not None:
        scenes.append((current_title, current_lines))
    return scenes


def color_for(line: str):
    if " fail" in line or "failed" in line or "E-" in line:
        return RED
    if " pass" in line:
        return GREEN
    if "not_executed" in line or "unknown" in line or "exit_code: 2" in line:
        return AMBER
    if line.startswith("disclosure:"):
        return MUTED
    return TEXT


def wrap(draw, text, font_obj, max_width):
    lines, current = [], ""
    for ch in text:
        if draw.textlength(current + ch, font=font_obj) <= max_width:
            current += ch
        else:
            lines.append(current)
            current = ch
    if current:
        lines.append(current)
    return lines


def draw_frame(step_title, lines, narration, visible, typing, progress, is_card=False,
               card_text=None):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    mono = font(FONT_MONO, 17)
    mono_small = font(FONT_MONO, 14)
    cjk = font(FONT_CJK, 23)
    title_font = font(FONT_CJK, 34)

    # title bar
    d.rounded_rectangle((32, 24, W - 32, H - 120), radius=12, fill=PANEL, outline=BORDER)
    for i, col in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
        d.ellipse((52 + i * 22, 42, 64 + i * 22, 54), fill=col)
    d.text((W - 250, 40), f"agentbridge  ·  {progress}", font=mono_small, fill=MUTED)

    if is_card:
        lines_wrapped = wrap(d, card_text or "", title_font, W - 200)
        y = 250
        for line in lines_wrapped:
            d.text((100, y), line, font=title_font, fill=TEXT)
            y += 52
        # footer
        d.text((100, H - 150), "github.com/wyjtopsc-ctrl/agentbridge",
               font=mono, fill=ACCENT)
        d.text((100, H - 118), "MIT  ·  pre-1.0  ·  hashes_only",
               font=mono_small, fill=MUTED)
        return img

    # step header
    d.text((56, 80), step_title, font=font(FONT_CJK, 24), fill=ACCENT)
    # command typed on first scene
    y = 128
    if progress.startswith("1/"):
        cmd = "$ PYTHONPATH=src python3 demo/run_demo.py"
        d.text((56, y), cmd[:typing], font=mono, fill=TEXT)
        y += 32
    shown = 0
    for line in lines:
        if shown >= visible:
            break
        color = color_for(line)
        d.text((56, y), line[:150], font=mono, fill=color)
        y += 26
        shown += 1

    # narration band
    d.rectangle((0, H - 108, W, H), fill=(1, 4, 9))
    d.line((0, H - 108, W, H - 108), fill=BORDER)
    sub_lines = wrap(d, narration, cjk, W - 120)
    yy = H - 92
    for line in sub_lines[:2]:
        d.text((60, yy), line, font=cjk, fill=TEXT)
        yy += 32
    d.text((W - 230, H - 40), "字幕 · 演示输出为真实运行",
           font=font(FONT_CJK, 14), fill=MUTED)
    return img


def main() -> int:
    scenes = capture_demo()
    storyboard = [("title", None, [])]
    for i, (title, lines) in enumerate(scenes, start=1):
        storyboard.append((f"step{i}", title, lines))
    storyboard.append(("end", None, []))

    frames = []
    durations = []
    # title card
    for _ in range(45):
        frames.append(draw_frame("", [], "", 0, 0, "0/10", True,
                                 "Agent 交付出了争议，怎么证明哪一版交给了谁？"))
    durations += [1 / FPS] * 45

    for idx, (kind, title, lines) in enumerate(storyboard[1:-1], start=1):
        narration = NARRATION.get(idx, "")
        duration = max(6.0, min(11.0, 3.2 + len(lines) * 0.55))
        n_frames = int(duration * FPS)
        for f in range(n_frames):
            t = f / FPS
            progress = f"{idx}/10"
            visible = min(len(lines), int((t - 0.8) / 0.45) + 1) if t > 0.8 else 0
            typing = min(len("$ PYTHONPATH=src python3 demo/run_demo.py"),
                         int(t * 55)) if idx == 1 else 0
            frames.append(draw_frame(title, lines, narration, max(0, visible),
                                     typing, progress))
    # end card
    for _ in range(60):
        frames.append(draw_frame("", [], "", 0, 0, "10/10", True,
                                 "它证明哪一版交给了谁、对方收没收到、记录有没有被改。"))
    durations += [1 / FPS] * 60

    out_mp4 = os.path.join(ROOT, "demo", "agentbridge-demo-zh.mp4")
    writer = imageio.get_writer(out_mp4, fps=FPS, codec="libx264", quality=8,
                                macro_block_size=None)
    for frame in frames:
        writer.append_data(np.asarray(frame))
    writer.close()
    # teaser GIF: verify + tamper + boundary (~last 30% of frames)
    gif_frames = frames[int(len(frames) * 0.62):int(len(frames) * 0.88):2]
    gif = [f.resize((640, 360), Image.LANCZOS) for f in gif_frames]
    out_gif = os.path.join(ROOT, "demo", "agentbridge-demo-teaser.gif")
    gif[0].save(out_gif, save_all=True, append_images=gif[1:], duration=120, loop=0,
                optimize=True)
    # thumbnail
    frames[len(frames) // 2].save(os.path.join(ROOT, "demo", "agentbridge-demo-thumb.png"))
    print("scenes:", len(scenes), "frames:", len(frames))
    print("mp4:", out_mp4, os.path.getsize(out_mp4))
    print("gif:", out_gif, os.path.getsize(out_gif))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
