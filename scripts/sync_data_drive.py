"""
Google Drive Dataset Integration & Sync Utility
Team Neural Breach — AI/ML-Based Cyber Defense Platform

Allows team members and CI/CD pipelines to sync the dataset from Google Drive:
Shared Folder: https://drive.google.com/drive/folders/1UHwqXR3qM-OHZc5nHNgkAVJ_Ewl_9Rha?usp=sharing
Folder ID: 1UHwqXR3qM-OHZc5nHNgkAVJ_Ewl_9Rha
"""

import os
import sys
import shutil
import argparse
import subprocess

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GDRIVE_FOLDER_ID = "1UHwqXR3qM-OHZc5nHNgkAVJ_Ewl_9Rha"
GDRIVE_SHARE_URL = f"https://drive.google.com/drive/folders/{GDRIVE_FOLDER_ID}?usp=sharing"

def check_local_gdrive_mount(custom_path: str = None) -> str | None:
    """Check if Google Drive for Desktop is already mounted locally."""
    candidates = [
        custom_path,
        os.path.expanduser("~/Google Drive/My Drive/aiml_project_team_neural_breach"),
        os.path.expanduser("~/GoogleDrive/My Drive/aiml_project_team_neural_breach"),
    ]
    # Scan macOS CloudStorage dynamically for any mounted Google Drive
    cloud_storage = os.path.expanduser("~/Library/CloudStorage")
    if os.path.exists(cloud_storage):
        for entry in os.listdir(cloud_storage):
            if "GoogleDrive" in entry:
                candidates.append(os.path.join(cloud_storage, entry, "My Drive", "aiml_project_team_neural_breach"))

    for p in candidates:
        if p and os.path.exists(p) and os.path.exists(os.path.join(p, "data")):
            return p
    return None


def link_from_local_mount(mount_path: str):
    """Link or copy data from mounted Google Drive to local project."""
    log(f"Detected mounted Google Drive at: {mount_path}")
    src_data = os.path.join(mount_path, "data")
    dst_data = os.path.join(PROJECT_ROOT, "data")

    # Link processed data directory
    src_proc = os.path.join(src_data, "processed")
    dst_proc = os.path.join(dst_data, "processed")
    if os.path.exists(src_proc):
        log(f"Syncing processed Parquet datasets from Drive...")
        shutil.copytree(src_proc, dst_proc, dirs_exist_ok=True)
        log("✓ Successfully synchronized processed datasets from Google Drive!")


def download_via_gdown(dest_dir: str):
    """Download Google Drive folder using gdown."""
    try:
        import gdown
    except ImportError:
        log("gdown not installed. Installing gdown...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "gdown"])
        import gdown

    log(f"Downloading dataset folder from Google Drive (ID: {GDRIVE_FOLDER_ID})...")
    url = f"https://drive.google.com/drive/folders/{GDRIVE_FOLDER_ID}"
    gdown.download_folder(url=url, output=dest_dir, quiet=False, use_cookies=False)
    log(f"✓ Download complete to: {dest_dir}")


def main():
    parser = argparse.ArgumentParser(description="Sync Team Neural Breach Datasets from Google Drive")
    parser.add_argument("--gdrive-path", type=str, default=None, help="Path to mounted Google Drive folder")
    parser.add_argument("--download", action="store_true", help="Download directly via gdown")
    parser.add_argument("--info", action="store_true", help="Print Google Drive link and access information")

    args = parser.parse_args()

    print("=" * 70)
    print("TEAM NEURAL BREACH — GOOGLE DRIVE DATASET RESOLVER")
    print("=" * 70)
    print(f"Google Drive Shared Folder: {GDRIVE_SHARE_URL}")
    print(f"Folder ID: {GDRIVE_FOLDER_ID}")
    print("-" * 70)

    if args.info:
        return

    # Check for local mount first
    mount = check_local_gdrive_mount(args.gdrive_path)
    if mount and not args.download:
        link_from_local_mount(mount)
    else:
        target = os.path.join(PROJECT_ROOT, "data")
        download_via_gdown(target)


if __name__ == "__main__":
    main()
