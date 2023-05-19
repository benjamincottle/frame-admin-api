use image::DynamicImage;
use std::{collections::HashMap, mem::replace};

const EPD_WIDTH: u32 = 600;
const EPD_HEIGHT: u32 = 448;
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
    let (nwidth, nheight, w, h) = match image.width() > image.height() {
        true => (
            EPD_WIDTH,
            EPD_HEIGHT,
            EPD_WIDTH as usize,
            EPD_HEIGHT as usize,
        ),
        false => (
            (EPD_WIDTH / 2),
            EPD_HEIGHT,
            (EPD_WIDTH / 2) as usize,
            EPD_HEIGHT as usize,
        ),
    };
    let mut data: Vec<u8> = Vec::with_capacity(w * h / 2);
    let mut buf: Vec<(u8, u8, u8)> = Vec::with_capacity(2);
    let image_buf = image
        .resize_to_fill(nwidth, nheight, image::imageops::FilterType::Lanczos3)
        .to_rgb8();
    let pixels = image_buf.as_flat_samples().to_vec().samples;
    let mut i = 0;
    let mut j = 1;
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
                buf = Vec::with_capacity(2);
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
    let (nwidth, nheight, w, h) = match data.len() == (EPD_WIDTH * EPD_HEIGHT / 2) as usize {
        true => (
            EPD_WIDTH,
            EPD_HEIGHT,
            EPD_WIDTH as usize,
            EPD_HEIGHT as usize,
        ),
        false => (
            (EPD_WIDTH / 2),
            EPD_HEIGHT,
            (EPD_WIDTH / 2) as usize,
            EPD_HEIGHT as usize,
        ),
    };
    let mut pixels: Vec<u8> = Vec::with_capacity(3 * w * h / 2);
    let mut buf: Vec<u8> = Vec::with_capacity(2);
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
            buf = Vec::with_capacity(2);
        }
    }
    let image_buf = image::ImageBuffer::from_raw(nwidth, nheight, pixels);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_nearest() {
        assert_eq!(get_nearest((0.0, 0.0, 0.0)), PALETTE[0]); // Black
        assert_eq!(get_nearest((255.0, 255.0, 255.0)), PALETTE[1]); // White
        assert_eq!(get_nearest((0.0, 255.0, 0.0)), PALETTE[2]); // Green
        assert_eq!(get_nearest((0.0, 0.0, 255.0)), PALETTE[3]); // Blue
        assert_eq!(get_nearest((255.0, 0.0, 0.0)), PALETTE[4]); // Red
        assert_eq!(get_nearest((255.0, 255.0, 0.0)), PALETTE[5]); // Yellow
        assert_eq!(get_nearest((255.0, 128.0, 0.0)), PALETTE[6]); // Orange
        assert_eq!(get_nearest((10.0, 10.0, 10.0)), PALETTE[0]); // Closest to Black
        assert_eq!(get_nearest((245.0, 245.0, 245.0)), PALETTE[1]); // Closest to White
        assert_eq!(get_nearest((10.0, 245.0, 10.0)), PALETTE[2]); // Closest to Green
        assert_eq!(get_nearest((50.0, 100.0, 150.0)), PALETTE[3]); // Closest to Blue
        assert_eq!(get_nearest((245.0, 10.0, 10.0)), PALETTE[4]); // Closest to Red
        assert_eq!(get_nearest((245.0, 245.0, 10.0)), PALETTE[5]); // Closest to Yellow
        assert_eq!(get_nearest((245.0, 118.0, 10.0)), PALETTE[6]); // Closest to Orange
    }

    #[test]
    fn test_add() {
        let c1 = (10.73, 23.87, 34.18);
        let c2 = (40.22, 50.035, 60.701);
        let result = add(c1, c2.0, c2.1, c2.2, 2.0);
        assert_eq!(
            (result.0, result.1, result.2),
            (13.24375, 26.997189, 37.973812)
        );
    }
}
