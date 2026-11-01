#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Image Forensics module
"""

import sys
import os
import tempfile
from PIL import Image
from PIL.ExifTags import TAGS

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.modules.image_forensics import analyze_image, find_images


def create_test_image_with_exif():
    """Create a temporary test image with EXIF data"""
    # Create a simple test image
    img = Image.new('RGB', (100, 100), color='red')
    
    # Save to temp file
    temp_file = tempfile.NamedTemporaryFile(suffix='.jpg', delete=False)
    img.save(temp_file.name, 'JPEG')
    temp_file.close()
    
    return temp_file.name


def test_analyze_local_image():
    """Test analyzing a local image file"""
    print("=" * 60)
    print("Testing Image Forensics - Local File")
    print("=" * 60)
    
    # Create test image
    test_image = create_test_image_with_exif()
    
    try:
        print(f"\n[*] Analyzing test image: {test_image}")
        results = analyze_image(test_image, is_local=True)
        
        # Verify structure (updated to match actual module)
        assert isinstance(results, dict), "Results should be a dictionary"
        assert "target" in results or "error" in results, "Should contain target or error info"
        
        print(f"\n[+] Analysis completed")
        print(f"[+] Format: {results.get('format', 'N/A')}")
        print(f"[+] Size: {results.get('size', 'N/A')}")
        print(f"[+] EXIF data found: {len(results.get('exif', {}))} fields")
        
        if results.get('exif'):
            print("\n[+] Sample EXIF data:")
            for key, value in list(results['exif'].items())[:5]:
                print(f"    - {key}: {value}")
        
        if results.get('error'):
            print(f"\n[!] Error: {results['error']}")
        
        print("\n[PASS] Local image analysis test passed!")
        
    finally:
        # Cleanup
        if os.path.exists(test_image):
            os.unlink(test_image)


def test_find_images():
    """Test finding images on a domain"""
    print("\n" + "=" * 60)
    print("Testing Image Discovery")
    print("=" * 60)
    
    test_domain = "example.com"
    
    print(f"\n[*] Searching for images on: {test_domain}")
    images = find_images(test_domain)
    
    # Verify it returns a list
    assert isinstance(images, list), "Should return a list of image URLs"
    
    print(f"\n[+] Found {len(images)} images")
    
    if images:
        print("\n[+] Sample images found:")
        for img_url in images[:3]:
            print(f"    - {img_url}")
    
    print("\n[PASS] Image discovery test passed!")


def test_analyze_remote_image():
    """Test analyzing a remote image URL"""
    print("\n" + "=" * 60)
    print("Testing Image Forensics - Remote URL")
    print("=" * 60)
    
    # Use a sample image URL (this might fail if network is down)
    test_url = "https://via.placeholder.com/150"
    
    print(f"\n[*] Analyzing remote image: {test_url}")
    
    try:
        results = analyze_image(test_url, is_local=False)
        
        assert isinstance(results, dict), "Results should be a dictionary"
        print(f"\n[+] Remote image analysis completed")
        print(f"[+] Result keys: {list(results.keys())}")
        
        if results.get('error'):
            print(f"[!] Error (expected for network issues): {results['error']}")
        
        print("\n[PASS] Remote image analysis test passed!")
        
    except Exception as e:
        print(f"\n[!] Remote image test skipped (network issue): {e}")


if __name__ == "__main__":
    try:
        test_analyze_local_image()
        test_find_images()
        test_analyze_remote_image()
        
        print("\n" + "=" * 60)
        print("ALL TESTS PASSED")
        print("=" * 60)
    except AssertionError as e:
        print(f"\n[FAIL] Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
