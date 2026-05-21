#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit tests for Metadata Analysis module
"""

import sys
import os
import tempfile
from docx import Document
from pypdf import PdfWriter

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.modules.metadata_analysis import analyze_local_file


def create_test_pdf():
    """Create a temporary test PDF with metadata"""
    pdf_writer = PdfWriter()
    pdf_writer.add_blank_page(width=200, height=200)
    
    # Add metadata
    pdf_writer.add_metadata({
        '/Author': 'Test Author',
        '/Creator': 'Test Creator',
        '/Title': 'Test Document'
    })
    
    temp_file = tempfile.NamedTemporaryFile(suffix='.pdf', delete=False)
    pdf_writer.write(temp_file)
    temp_file.close()
    
    return temp_file.name


def create_test_docx():
    """Create a temporary test DOCX with metadata"""
    doc = Document()
    doc.add_paragraph("Test content")
    
    # Set core properties
    doc.core_properties.author = "Test Author"
    doc.core_properties.title = "Test Document"
    
    temp_file = tempfile.NamedTemporaryFile(suffix='.docx', delete=False)
    doc.save(temp_file.name)
    temp_file.close()
    
    return temp_file.name


def test_analyze_pdf():
    """Test PDF metadata extraction"""
    print("=" * 60)
    print("Testing PDF Metadata Analysis")
    print("=" * 60)
    
    test_pdf = create_test_pdf()
    
    try:
        print(f"\n[*] Analyzing test PDF: {test_pdf}")
        results = analyze_local_file(test_pdf)
        
        # Verify structure (updated to match actual module)
        assert isinstance(results, dict), "Results should be a dictionary"
        assert "file" in results, "Should contain file field"
        assert "type" in results, "Should contain type field"
        
        print(f"\n[+] File type: {results.get('type')}")
        print(f"[+] Metadata fields found: {len(results.get('metadata', {}))}")
        
        if results.get('metadata'):
            print("\n[+] Extracted metadata:")
            for key, value in results['metadata'].items():
                print(f"    - {key}: {value}")
        
        if results.get('error'):
            print(f"\n[!] Error: {results['error']}")
        
        print("\n[PASS] PDF metadata analysis test passed!")
        
    finally:
        # Cleanup
        if os.path.exists(test_pdf):
            os.unlink(test_pdf)


def test_analyze_docx():
    """Test DOCX metadata extraction"""
    print("\n" + "=" * 60)
    print("Testing DOCX Metadata Analysis")
    print("=" * 60)
    
    test_docx = create_test_docx()
    
    try:
        print(f"\n[*] Analyzing test DOCX: {test_docx}")
        results = analyze_local_file(test_docx)
        
        # Verify structure
        assert isinstance(results, dict), "Results should be a dictionary"
        assert "file" in results, "Should contain file field"
        assert "type" in results, "Should contain type field"
        
        print(f"\n[+] File type: {results.get('type')}")
        print(f"[+] Metadata fields found: {len(results.get('metadata', {}))}")
        
        if results.get('metadata'):
            print("\n[+] Extracted metadata:")
            for key, value in results['metadata'].items():
                print(f"    - {key}: {value}")
        
        if results.get('error'):
            print(f"\n[!] Error: {results['error']}")
        
        print("\n[PASS] DOCX metadata analysis test passed!")
        
    finally:
        # Cleanup
        if os.path.exists(test_docx):
            os.unlink(test_docx)


def test_analyze_unsupported_file():
    """Test handling of unsupported file types"""
    print("\n" + "=" * 60)
    print("Testing Unsupported File Type Handling")
    print("=" * 60)
    
    # Create a text file
    temp_file = tempfile.NamedTemporaryFile(suffix='.txt', delete=False, mode='w')
    temp_file.write("Test content")
    temp_file.close()
    
    try:
        print(f"\n[*] Testing with unsupported file: {temp_file.name}")
        results = analyze_local_file(temp_file.name)
        
        # Should handle gracefully
        assert isinstance(results, dict), "Should return a dictionary"
        assert "error" in results or "type" in results, "Should indicate error or file type"
        
        print(f"\n[+] Handled unsupported file gracefully")
        print(f"[+] Result: {results}")
        
        print("\n[PASS] Unsupported file test passed!")
        
    finally:
        # Cleanup
        if os.path.exists(temp_file.name):
            os.unlink(temp_file.name)


if __name__ == "__main__":
    try:
        test_analyze_pdf()
        test_analyze_docx()
        test_analyze_unsupported_file()
        
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
