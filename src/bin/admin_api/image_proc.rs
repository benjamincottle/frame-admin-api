use image::DynamicImage;
use std::{collections::HashMap, mem::replace};

const WIDTH: u32 = 600;
const HEIGHT: u32 = 448;
const PALETTE: [(u8, u8, u8); 7] = [
    (0, 0, 0),       // Black
    (255, 255, 255), // White
    (0, 255, 0),     // Green
    (0, 0, 255),     // Blue
    (255, 0, 0),     // Red
    (255, 255, 0),   // Yellow
    (255, 128, 0),   // Orange
];

fn get_nearest(colour: (f32, f32, f32)) -> (u8, u8, u8) {
    let mut nearest_palette_index = 0;
    let mut lowest_error = (colour.0 - PALETTE[0].0 as f32).powf(2.0)
        + (colour.1 - PALETTE[0].1 as f32).powf(2.0)
        + (colour.2 - PALETTE[0].2 as f32).powf(2.0);
    for i in 1..PALETTE.len() {
        let candidate_error = (colour.0 - PALETTE[i].0 as f32).powf(2.0)
            + (colour.1 - PALETTE[i].1 as f32).powf(2.0)
            + (colour.2 - PALETTE[i].2 as f32).powf(2.0);
        if candidate_error < lowest_error {
            lowest_error = candidate_error;
            nearest_palette_index = i;
        }
    }
    PALETTE[nearest_palette_index]
}

fn add(colour: (f32, f32, f32), r: f32, g: f32, b: f32, k: f32) -> (f32, f32, f32) {
    (
        colour.0 + (r * k / 32.0),
        colour.1 + (g * k / 32.0),
        colour.2 + (b * k / 32.0),
    )
}

pub fn encode_image(image: &DynamicImage) -> Vec<u8> {
    let map: HashMap<(u8, u8, u8), u8> = PALETTE
        .iter()
        .enumerate()
        .map(|(i, &rgb)| (rgb, i as u8))
        .collect();
    let mut data: Vec<u8> = Vec::new();
    let mut buf: Vec<(u8, u8, u8)> = Vec::new();
    let image_buf = image
        .resize_exact(WIDTH, HEIGHT, image::imageops::FilterType::Lanczos3)
        .to_rgb8();
    let pixels = image_buf.as_flat_samples().to_vec().samples;
    let mut i = 0;
    let mut j = 1;
    let w = WIDTH as usize;
    let h = HEIGHT as usize;
    let mut e: Vec<Vec<(f32, f32, f32)>> = vec![vec![(0.0, 0.0, 0.0); w]; 2];
    for y in 0..h {
        i = replace(&mut j, i);
        e[j] = vec![(0.0, 0.0, 0.0); w];
        for x in 0..w {
            let r = pixels[((y * w + x) * 3) + 0] as f32 + e[i][x].0;
            let g = pixels[((y * w + x) * 3) + 1] as f32 + e[i][x].1;
            let b = pixels[((y * w + x) * 3) + 2] as f32 + e[i][x].2;
            let q_colour = get_nearest((r, g, b));
            buf.push(q_colour);
            if buf.len() == 2 {
                let p1 = map[&buf[0]];
                let p2 = map[&buf[1]];
                data.push((p1 << 4) + p2);
                buf = Vec::new();
            }
            let r = r - q_colour.0 as f32;
            let g = g - q_colour.1 as f32;
            let b = b - q_colour.2 as f32;
            if x == 0 {
                e[j][x] = add(e[j][x], r, g, b, 7.0);
                e[j][x + 1] = add(e[j][x + 1], r, g, b, 2.0);
                e[i][x + 1] = add(e[i][x + 1], r, g, b, 7.0);
            } else if x == w - 1 {
                e[j][x - 1] = add(e[j][x - 1], r, g, b, 7.0);
                e[j][x] = add(e[j][x], r, g, b, 9.0);
            } else {
                e[j][x - 1] = add(e[j][x - 1], r, g, b, 7.0);
                e[j][x] = add(e[j][x], r, g, b, 9.0);
                e[j][x + 1] = add(e[j][x + 1], r, g, b, 2.0);
                e[i][x + 1] = add(e[i][x + 1], r, g, b, 7.0);
            }
        }
    }
    data
}

pub fn decode_image(data: Vec<u8>) -> Result<DynamicImage, Box<dyn std::error::Error>> {
    let map: HashMap<u8, (u8, u8, u8)> = PALETTE
        .iter()
        .enumerate()
        .map(|(i, &rgb)| (i as u8, rgb))
        .collect();
    let mut pixels: Vec<u8> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    for byte in data {
        let p1 = byte >> 4;
        let p2 = byte & 0x0F;
        buf.push(p1);
        buf.push(p2);
        if buf.len() == 2 {
            let p1 = map[&buf[0]];
            let p2 = map[&buf[1]];
            pixels.push(p1.0);
            pixels.push(p1.1);
            pixels.push(p1.2);
            pixels.push(p2.0);
            pixels.push(p2.1);
            pixels.push(p2.2);
            buf = Vec::new();
        }
    }
    let image_buf = image::ImageBuffer::from_raw(WIDTH, HEIGHT, pixels);
    let dimage = match image_buf {
        Some(buf) => DynamicImage::ImageRgb8(buf),
        None => {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "(decode_image) Invalid image data image_buf is None",
            )));
        }
    };
    Ok(dimage)
}
