import sys
import os
import argparse
from PIL import Image
from moviepy.video.io.VideoFileClip import VideoFileClip
import ffmpeg
import tempfile

def compress_image(input_path, output_path, target_size_kb):
    img = Image.open(input_path)
    quality = 95

    while quality > 5:
        img.save(output_path, optimize=True, quality=quality)
        current_size_kb = os.path.getsize(output_path) / 1024
        if current_size_kb <= target_size_kb:
            break
        quality -= 5

    if quality <= 5:
        print("Warning: Could not compress image to desired size.")

def compress_video(input_path, output_path, target_size_kb):
    temp_output = tempfile.NamedTemporaryFile(delete=False, suffix=".mp4").name

    # Estimate bitrate (in kbps)
    clip = VideoFileClip(input_path)
    duration = clip.duration
    target_bitrate = (target_size_kb * 8) / duration  # kbps

    # Explicitly set ffmpeg path (uncomment and adjust if needed)
    # ffmpeg._ffmpeg._ffmpeg_dir = '/usr/bin/ffmpeg'  # Replace with actual path

    # Run ffmpeg to compress
    ffmpeg.input(input_path).output(
        temp_output,
        **{
            'b:v': f'{int(target_bitrate)}k',
            'preset': 'slow',
            'movflags': '+faststart'
        }
    ).run(overwrite_output=True, quiet=True)

    final_size_kb = os.path.getsize(temp_output) / 1024
    if final_size_kb <= target_size_kb:
        os.rename(temp_output, output_path)
    else:
        print("Warning: Could not compress video to desired size.")
        os.rename(temp_output, output_path)

def main():
    parser = argparse.ArgumentParser(description="Compress image or video to target file size.")
    parser.add_argument("input", help="Input image or video file.")
    parser.add_argument("-size", type=str, required=True, help="Target size in kilobytes, e.g., 256kb")
    parser.add_argument("-o", "--output", type=str, default="output", help="Output filename (without extension)")

    args = parser.parse_args()

    # Parse size
    size_str = args.size.lower().replace("kb", "")
    try:
        target_size_kb = int(size_str)
    except ValueError:
        print("Invalid size format. Use something like -size 256kb")
        return

    input_ext = os.path.splitext(args.input)[1].lower()
    output_ext = input_ext if input_ext in [".jpg", ".jpeg", ".png", ".mp4", ".mov", ".avi"] else ".out"

    output_file = args.output + output_ext

    if input_ext in [".jpg", ".jpeg", ".png"]:
        compress_image(args.input, output_file, target_size_kb)
    elif input_ext in [".mp4", ".mov", ".avi"]:
        compress_video(args.input, output_file, target_size_kb)
    else:
        print("Unsupported file type.")

    print(f"Saved to: {output_file}")

if __name__ == "__main__":

    # sendfile test-data/images/small.jpg
    # sendfile test-data/images/med.jpg
    # sendfile test-data/images/large.jpg

    # sendfile test-data/videos/small.mp4
    # sendfile test-data/videos/med.mp4
    # sendfile test-data/videos/large.mp4

    # sendfile test-data/csv/small.csv
    # sendfile test-data/csv/med.csv
    # sendfile test-data/csv/large.csv

    # sendfile test-data/pdf/small.pdf
    # sendfile test-data/pdf/med.pdf
    # sendfile test-data/pdf/large.pdf
    main()