package adapter

import (
	"bytes"
	"encoding/base64"
	"errors"
	"image"
	"image/color"
	"image/draw"
	_ "image/gif"
	"image/jpeg"
	_ "image/png"
	"strings"
)

const (
	defaultMaxImageDimension = 1024
	defaultJPEGQuality       = 82
)

func optimizeImageURL(rawURL string) (string, bool, error) {
	if !strings.HasPrefix(strings.ToLower(rawURL), "data:image/") {
		return rawURL, false, nil
	}

	header, encoded, ok := strings.Cut(rawURL, ",")
	if !ok || !strings.Contains(strings.ToLower(header), ";base64") {
		return "", false, errors.New("image_url data URL must be base64 encoded")
	}

	imageBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", false, errors.New("image_url data URL contains invalid base64")
	}

	img, _, err := image.Decode(bytes.NewReader(imageBytes))
	if err != nil {
		return "", false, errors.New("image_url data URL contains an unsupported image")
	}

	resized := resizeImage(img, defaultMaxImageDimension)
	var out bytes.Buffer
	if err := jpeg.Encode(&out, resized, &jpeg.Options{Quality: defaultJPEGQuality}); err != nil {
		return "", false, err
	}
	if out.Len() >= len(imageBytes) {
		return rawURL, false, nil
	}

	optimized := "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(out.Bytes())
	return optimized, true, nil
}

func resizeImage(src image.Image, maxDimension int) image.Image {
	bounds := src.Bounds()
	srcW := bounds.Dx()
	srcH := bounds.Dy()
	if srcW <= 0 || srcH <= 0 || maxDimension <= 0 {
		return flattenImage(src, bounds)
	}

	dstW, dstH := srcW, srcH
	if srcW > maxDimension || srcH > maxDimension {
		if srcW >= srcH {
			dstW = maxDimension
			dstH = max(1, srcH*maxDimension/srcW)
		} else {
			dstH = maxDimension
			dstW = max(1, srcW*maxDimension/srcH)
		}
	}

	dst := image.NewRGBA(image.Rect(0, 0, dstW, dstH))
	draw.Draw(dst, dst.Bounds(), &image.Uniform{C: color.White}, image.Point{}, draw.Src)
	for y := 0; y < dstH; y++ {
		srcY := bounds.Min.Y + y*srcH/dstH
		for x := 0; x < dstW; x++ {
			srcX := bounds.Min.X + x*srcW/dstW
			dst.Set(x, y, blendOverWhite(src.At(srcX, srcY)))
		}
	}
	return dst
}

func flattenImage(src image.Image, bounds image.Rectangle) image.Image {
	dst := image.NewRGBA(image.Rect(0, 0, bounds.Dx(), bounds.Dy()))
	draw.Draw(dst, dst.Bounds(), &image.Uniform{C: color.White}, image.Point{}, draw.Src)
	for y := 0; y < bounds.Dy(); y++ {
		for x := 0; x < bounds.Dx(); x++ {
			dst.Set(x, y, blendOverWhite(src.At(bounds.Min.X+x, bounds.Min.Y+y)))
		}
	}
	return dst
}

func blendOverWhite(c color.Color) color.RGBA {
	r, g, b, a := c.RGBA()
	alpha := a / 257
	if alpha >= 255 {
		return color.RGBA{R: uint8(r / 257), G: uint8(g / 257), B: uint8(b / 257), A: 255}
	}
	return color.RGBA{
		R: uint8((r/257*alpha + 255*(255-alpha)) / 255),
		G: uint8((g/257*alpha + 255*(255-alpha)) / 255),
		B: uint8((b/257*alpha + 255*(255-alpha)) / 255),
		A: 255,
	}
}
