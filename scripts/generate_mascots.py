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


def draw_teen(scale, skin, hair, jacket, shirt, trousers, shoes, bob, wave, style):
    sprite = Image.new("RGBA", (270, 380), (0, 0, 0, 0))
    draw = ImageDraw.Draw(sprite)
    ink = (37, 43, 65, 255)
    white = (255, 252, 244, 255)
    shift = int(bob)

    draw.ellipse((44, 345 + shift, 225, 365 + shift), fill=(40, 47, 65, 28))

    draw.line((111, 267 + shift, 99, 326 + shift), fill=ink, width=22)
    draw.line((164, 267 + shift, 178, 326 + shift), fill=ink, width=22)
    draw.line((111, 271 + shift, 101, 325 + shift), fill=trousers, width=15)
    draw.line((164, 271 + shift, 176, 325 + shift), fill=trousers, width=15)
    rounded(draw, (76, 322 + shift, 121, 347 + shift), 12, shoes, ink, 5)
    rounded(draw, (160, 322 + shift, 207, 347 + shift), 12, shoes, ink, 5)
    draw.line((85, 337 + shift, 110, 337 + shift), fill=(177, 187, 202, 255), width=3)
    draw.line((170, 337 + shift, 196, 337 + shift), fill=(177, 187, 202, 255), width=3)

    rounded(draw, (81, 156 + shift, 195, 284 + shift), 29, trousers, ink, 6)
    draw.line((138, 169 + shift, 138, 278 + shift), fill=ink, width=4)
    rounded(draw, (157, 220 + shift, 185, 249 + shift), 6, (94, 113, 131, 255), ink, 3)
    draw.line((162, 229 + shift, 180, 229 + shift), fill=(228, 204, 150, 255), width=3)

    draw.line((82, 176 + shift, 38, 208 + shift, 27, 170 + shift + wave), fill=ink, width=26, joint="curve")
    draw.line((82, 176 + shift, 38, 208 + shift, 27, 170 + shift + wave), fill=jacket, width=18, joint="curve")
    draw.line((27, 170 + shift + wave, 16, 159 + shift + wave), fill=skin, width=17)
    draw.line((190, 176 + shift, 226, 196 + shift, 240, 157 + shift - wave), fill=ink, width=26, joint="curve")
    draw.line((190, 176 + shift, 226, 196 + shift, 240, 157 + shift - wave), fill=jacket, width=18, joint="curve")
    draw.line((240, 157 + shift - wave, 247, 142 + shift - wave), fill=skin, width=17)

    rounded(draw, (119, 132 + shift, 158, 178 + shift), 14, skin)
    rounded(draw, (72, 162 + shift, 199, 280 + shift), 26, jacket, ink, 6)
    rounded(draw, (119, 167 + shift, 153, 231 + shift), 8, shirt)
    draw.line((137, 168 + shift, 137, 223 + shift), fill=ink, width=3)
    rounded(draw, (80, 225 + shift, 107, 257 + shift), 5, jacket, ink, 3)
    rounded(draw, (164, 225 + shift, 190, 257 + shift), 5, jacket, ink, 3)
    draw.ellipse((88, 238 + shift, 98, 248 + shift), fill=(255, 224, 147, 255))
    draw.ellipse((172, 238 + shift, 182, 248 + shift), fill=(255, 224, 147, 255))

    draw.ellipse((75, 47 + shift, 193, 173 + shift), fill=skin, outline=ink, width=5)
    draw.ellipse((65, 94 + shift, 84, 121 + shift), fill=skin, outline=ink, width=4)
    draw.ellipse((184, 94 + shift, 203, 121 + shift), fill=skin, outline=ink, width=4)

    if style == "curly":
        draw.ellipse((74, 28 + shift, 190, 112 + shift), fill=hair, outline=ink, width=5)
        for x, y, radius in [(82, 49, 23), (110, 31, 24), (142, 30, 25), (171, 43, 23), (184, 62, 18)]:
            draw.ellipse((x - radius, y - radius + shift, x + radius, y + radius + shift), fill=hair, outline=ink, width=4)
        draw.arc((89, 34 + shift, 168, 89 + shift), 195, 340, fill=(221, 167, 114, 255), width=5)
    else:
        draw.ellipse((71, 28 + shift, 196, 111 + shift), fill=hair, outline=ink, width=5)
        rounded(draw, (69, 41 + shift, 193, 84 + shift), 18, hair, ink, 4)
        draw.polygon([(91, 63 + shift), (160, 56 + shift), (185, 77 + shift), (148, 91 + shift), (100, 83 + shift)], fill=hair)
        rounded(draw, (71, 25 + shift, 195, 63 + shift), 16, (89, 154, 192, 255), ink, 4)
        draw.arc((85, 33 + shift, 180, 75 + shift), 190, 345, fill=(255, 196, 130, 255), width=4)

    draw.line((101, 99 + shift, 119, 96 + shift), fill=ink, width=4)
    draw.line((151, 96 + shift, 170, 99 + shift), fill=ink, width=4)
    draw.ellipse((105, 105 + shift, 116, 119 + shift), fill=ink)
    draw.ellipse((156, 105 + shift, 167, 119 + shift), fill=ink)
    draw.ellipse((88, 127 + shift, 108, 139 + shift), fill=(244, 151, 145, 150))
    draw.ellipse((166, 127 + shift, 186, 139 + shift), fill=(244, 151, 145, 150))
    draw.arc((119, 116 + shift, 154, 151 + shift), 10, 168, fill=ink, width=4)
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
    left = draw_teen(0.96, (177, 112, 83, 255), (43, 39, 54, 255), (226, 102, 99, 255), (255, 225, 200, 255), (54, 65, 91, 255), (255, 250, 239, 255), 5 * sin(phase), int(8 * sin(phase * 2)), "curly")
    right = draw_teen(0.82, (219, 164, 120, 255), (52, 44, 42, 255), (74, 151, 190, 255), (228, 242, 241, 255), (103, 113, 137, 255), (255, 250, 239, 255), 6 * sin(phase + 1.0), int(7 * sin(phase * 2 + 1.0)), "beanie")
    canvas.alpha_composite(left, (222, 40 + int(5 * sin(phase))))
    canvas.alpha_composite(right, (505, 101 + int(6 * sin(phase + 1.0))))
    frames.append(canvas.convert("P", palette=Image.Palette.ADAPTIVE, colors=128))

frames[0].save("phone-mascots.gif", save_all=True, append_images=frames[1:], duration=85, loop=0, optimize=True, disposal=2)
