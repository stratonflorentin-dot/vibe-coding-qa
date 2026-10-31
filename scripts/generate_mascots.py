from math import cos, pi, sin
from PIL import Image, ImageDraw

WIDTH = 960
HEIGHT = 440
FRAME_COUNT = 28


def rounded(draw, box, radius, fill, outline=None, width=1):
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)


def star(draw, center_x, center_y, radius, fill):
    points = []
    for index in range(8):
        angle = -pi / 2 + index * pi / 4
        distance = radius if index % 2 == 0 else radius * 0.28
        points.append((center_x + distance * cos(angle), center_y + distance * sin(angle)))
    draw.polygon(points, fill=fill)


def draw_brother(scale, skin, shirt, overalls, cap, shoes, bob, wave, initial):
    sprite = Image.new("RGBA", (270, 380), (0, 0, 0, 0))
    draw = ImageDraw.Draw(sprite)
    ink = (37, 43, 65, 255)
    white = (255, 252, 244, 255)
    shift = int(bob)

    draw.ellipse((44, 345 + shift, 225, 365 + shift), fill=(40, 47, 65, 28))

    draw.line((111, 267 + shift, 99, 326 + shift), fill=ink, width=22)
    draw.line((164, 267 + shift, 178, 326 + shift), fill=ink, width=22)
    draw.line((111, 271 + shift, 101, 325 + shift), fill=overalls, width=15)
    draw.line((164, 271 + shift, 176, 325 + shift), fill=overalls, width=15)
    rounded(draw, (76, 322 + shift, 121, 347 + shift), 12, shoes, ink, 5)
    rounded(draw, (160, 322 + shift, 207, 347 + shift), 12, shoes, ink, 5)
    draw.line((85, 337 + shift, 110, 337 + shift), fill=(177, 187, 202, 255), width=3)
    draw.line((170, 337 + shift, 196, 337 + shift), fill=(177, 187, 202, 255), width=3)

    rounded(draw, (81, 156 + shift, 195, 284 + shift), 29, shirt, ink, 6)
    draw.polygon([(91, 163 + shift), (119, 169 + shift), (124, 274 + shift), (98, 274 + shift)], fill=overalls, outline=ink)
    draw.polygon([(184, 163 + shift), (156, 169 + shift), (151, 274 + shift), (177, 274 + shift)], fill=overalls, outline=ink)
    rounded(draw, (96, 205 + shift, 180, 282 + shift), 12, overalls, ink, 5)
    rounded(draw, (116, 235 + shift, 160, 265 + shift), 6, shirt, ink, 3)
    draw.ellipse((83, 215 + shift, 99, 231 + shift), fill=(255, 220, 116, 255), outline=ink, width=2)
    draw.ellipse((177, 215 + shift, 193, 231 + shift), fill=(255, 220, 116, 255), outline=ink, width=2)

    draw.line((82, 176 + shift, 38, 208 + shift, 27, 170 + shift + wave), fill=ink, width=26, joint="curve")
    draw.line((82, 176 + shift, 38, 208 + shift, 27, 170 + shift + wave), fill=shirt, width=18, joint="curve")
    draw.line((27, 170 + shift + wave, 16, 159 + shift + wave), fill=skin, width=17)
    draw.line((190, 176 + shift, 226, 196 + shift, 240, 157 + shift - wave), fill=ink, width=26, joint="curve")
    draw.line((190, 176 + shift, 226, 196 + shift, 240, 157 + shift - wave), fill=shirt, width=18, joint="curve")
    draw.line((240, 157 + shift - wave, 247, 142 + shift - wave), fill=skin, width=17)

    draw.ellipse((8, 148 + shift + wave, 34, 174 + shift + wave), fill=white, outline=ink, width=4)
    draw.ellipse((232, 131 + shift - wave, 258, 158 + shift - wave), fill=white, outline=ink, width=4)

    rounded(draw, (119, 132 + shift, 158, 178 + shift), 14, skin)
    rounded(draw, (72, 162 + shift, 199, 280 + shift), 26, shirt, ink, 6)
    draw.polygon([(89, 164 + shift), (112, 170 + shift), (122, 275 + shift), (99, 275 + shift)], fill=overalls, outline=ink)
    draw.polygon([(182, 164 + shift), (159, 170 + shift), (149, 275 + shift), (173, 275 + shift)], fill=overalls, outline=ink)
    rounded(draw, (96, 205 + shift, 180, 282 + shift), 12, overalls, ink, 5)
    rounded(draw, (116, 235 + shift, 160, 265 + shift), 6, shirt, ink, 3)
    draw.ellipse((83, 215 + shift, 99, 231 + shift), fill=(255, 220, 116, 255), outline=ink, width=2)
    draw.ellipse((177, 215 + shift, 193, 231 + shift), fill=(255, 220, 116, 255), outline=ink, width=2)

    draw.ellipse((75, 47 + shift, 193, 173 + shift), fill=skin, outline=ink, width=5)
    draw.ellipse((65, 94 + shift, 84, 121 + shift), fill=skin, outline=ink, width=4)
    draw.ellipse((184, 94 + shift, 203, 121 + shift), fill=skin, outline=ink, width=4)
    draw.ellipse((73, 27 + shift, 197, 103 + shift), fill=cap, outline=ink, width=5)
    rounded(draw, (55, 70 + shift, 214, 101 + shift), 15, cap, ink, 4)
    draw.ellipse((111, 41 + shift, 159, 86 + shift), fill=white, outline=ink, width=3)
    if initial == "M":
        draw.line((121, 75 + shift, 121, 53 + shift, 135, 66 + shift, 149, 53 + shift, 149, 75 + shift), fill=cap, width=5, joint="curve")
    else:
        draw.line((124, 52 + shift, 124, 76 + shift, 148, 76 + shift), fill=cap, width=6, joint="curve")

    draw.line((101, 99 + shift, 119, 96 + shift), fill=ink, width=4)
    draw.line((151, 96 + shift, 170, 99 + shift), fill=ink, width=4)
    draw.ellipse((105, 105 + shift, 116, 119 + shift), fill=ink)
    draw.ellipse((156, 105 + shift, 167, 119 + shift), fill=ink)
    draw.ellipse((88, 127 + shift, 108, 139 + shift), fill=(244, 151, 145, 150))
    draw.ellipse((166, 127 + shift, 186, 139 + shift), fill=(244, 151, 145, 150))
    draw.arc((119, 116 + shift, 154, 151 + shift), 10, 168, fill=ink, width=4)
    draw.ellipse((101, 130 + shift, 137, 147 + shift), fill=ink)
    draw.ellipse((136, 130 + shift, 172, 147 + shift), fill=ink)
    draw.arc((80, 147 + shift, 191, 179 + shift), 190, 350, fill=ink, width=4)

    draw.line((103, 176 + shift, 113, 189 + shift), fill=(255, 221, 135, 255), width=4)
    draw.line((171, 176 + shift, 181, 189 + shift), fill=(255, 221, 135, 255), width=4)

    return sprite.resize((int(sprite.width * scale), int(sprite.height * scale)), Image.Resampling.LANCZOS)


def draw_background(frame_index):
    image = Image.new("RGB", (WIDTH, HEIGHT), (255, 249, 240))
    draw = ImageDraw.Draw(image)
    for y in range(HEIGHT):
        blend = y / HEIGHT
        color = (int(255 - 5 * blend), int(249 - 6 * blend), int(240 + blend))
        draw.line((0, y, WIDTH, y), fill=color)
    rounded(draw, (18, 18, WIDTH - 19, HEIGHT - 19), 38, None, (235, 225, 212), 3)
    draw.ellipse((58, 53, 237, 232), fill=(231, 245, 242))
    draw.ellipse((724, 211, 895, 382), fill=(248, 232, 220))
    draw.ellipse((782, 66, 811, 95), fill=(255, 224, 144))
    accents = [(273, 92, 16), (692, 102, 13), (814, 162, 9), (117, 302, 11), (397, 332, 8), (683, 353, 12), (534, 74, 8)]
    for index, (x, y, radius) in enumerate(accents):
        pulse = 0.55 + 0.45 * sin(2 * pi * frame_index / FRAME_COUNT + index)
        color = (255, int(165 + 55 * pulse), int(118 + 36 * pulse)) if index % 2 == 0 else (85, int(168 + 45 * pulse), 191)
        star(draw, x, y, int(radius * (0.72 + 0.28 * pulse)), color)
    for x, y in [(251, 264), (730, 135), (350, 149), (617, 264), (194, 112), (861, 273)]:
        draw.ellipse((x - 4, y - 4, x + 4, y + 4), fill=(113, 186, 174))
    return image.convert("RGBA")


frames = []
for frame_index in range(FRAME_COUNT):
    phase = 2 * pi * frame_index / FRAME_COUNT
    canvas = draw_background(frame_index)
    left = draw_brother(0.96, (177, 112, 83, 255), (226, 58, 54, 255), (45, 91, 168, 255), (219, 49, 45, 255), (112, 69, 48, 255), 5 * sin(phase), int(8 * sin(phase * 2)), "M")
    right = draw_brother(0.82, (219, 164, 120, 255), (52, 158, 82, 255), (45, 91, 168, 255), (45, 158, 81, 255), (112, 69, 48, 255), 6 * sin(phase + 1.0), int(7 * sin(phase * 2 + 1.0)), "L")
    canvas.alpha_composite(left, (222, 40 + int(5 * sin(phase))))
    canvas.alpha_composite(right, (505, 101 + int(6 * sin(phase + 1.0))))
    frames.append(canvas.convert("P", palette=Image.Palette.ADAPTIVE, colors=128))

frames[0].save("phone-mascots.gif", save_all=True, append_images=frames[1:], duration=85, loop=0, optimize=True, disposal=2)
